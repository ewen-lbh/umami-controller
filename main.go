package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/sirupsen/logrus"
	"github.com/spotahome/kooper/v2/controller"
	kooperlogrus "github.com/spotahome/kooper/v2/log/logrus"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

var nginxSnippetTemplate, _ = template.New("nginx snippet").Parse(`
	sub_filter "</head>" "<script async src=https://stats.inpt.fr/script.js data-website-id={{ .ID }}></script></head>";
	# The http_sub_module doesn't support compression from the ingress to the backend application
	proxy_set_header Accept-Encoding "";
`)

type annotationPatch struct {
	Metadata struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
}

func run() error {
	logger := kooperlogrus.New(logrus.NewEntry(logrus.New()))
	k8sconfig, err := rest.InClusterConfig()
	if err != nil {
		// No in cluster? letr's try locally
		kubehome := filepath.Join(homedir.HomeDir(), ".kube", "config")
		k8sconfig, err = clientcmd.BuildConfigFromFlags("", kubehome)
		if err != nil {
			return fmt.Errorf("error loading kubernetes configuration: %w", err)
		}
	}
	k8scli, _ := kubernetes.NewForConfig(k8sconfig)
	retriever := controller.MustRetrieverFromListerWatcher(&cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return k8scli.NetworkingV1().Ingresses("").List(context.Background(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return k8scli.NetworkingV1().Ingresses("").Watch(context.Background(), options)
		},
	})

	handler := controller.HandlerFunc(func(ctx context.Context, o runtime.Object) error {
		ingress := o.(*networkingv1.Ingress)
		// Return early if the umami.is/inject annotation is not found
		modeOrHost := ""
		title := ""
		for key, val := range ingress.Annotations {
			if key == "umami.is/inject" {
				modeOrHost = val
			}
			if key == "umami.is/name" {
				title = val
			}
		}
		if modeOrHost == "" {
			logger.Debugf("Skipping resource, no annotation")
			return nil
		}
		hosts := mapset.NewSet[string]()
		if modeOrHost == "all" {
			for _, rule := range ingress.Spec.Rules {
				hosts.Add(rule.Host)
			}
		} else {
			hosts.Add(modeOrHost)
		}

		logger.Infof("%s/%s: Injecting in %v (umami.is/inject=%s)", ingress.Namespace, ingress.Name, hosts, modeOrHost)
		annotations := ingress.DeepCopy().Annotations

		umami := Umami{
			Namespace:      os.Getenv("NAMESPACE"),
			AdminSecretRef: os.Getenv("ADMIN_SECRET_REF"),
			Host:           os.Getenv("HOST"),
		}

		adminSecret, err := k8scli.CoreV1().Secrets(umami.Namespace).Get(ctx, umami.AdminSecretRef, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("while getting umami controller admin secret: %w", err)
		}

		username := string(adminSecret.Data["USERNAME"])
		password := string(adminSecret.Data["PASSWORD"])

		// Authenticate to the Umami API, get a token
		logger.Infof("Authenticating to the Umami API")
		creds, err := apiRequest[authPayload, authResponse](&umami, "POST", "/api/auth/login", "", authPayload{
			Username: username,
			Password: password,
		})
		if err != nil {
			return fmt.Errorf("while authenticating: %w", err)
		}

		logger.Infof("Successfully logged into Umami as %s", creds.User.Username)

		// Hit the API to see if the website already exists in Umami
		logger.Infof("Checking if the website already exists in Umami")

		websites, err := apiQuery[websitesListResponse](&umami, "/api/websites", creds.Token)
		if err != nil {
			return fmt.Errorf("while fetching the websites: %w", err)
		}

		logger.Infof("Found %d websites in Umami, looking for %v", websites.Count, hosts)

		for host := range hosts.Iter() {
			umamiWebsite := umamiWebsite{}
			found := false
			for _, website := range websites.Data {
				if website.Domain == host {
					logger.Infof("Website exists, OK")
					umamiWebsite = website
					found = true
					break
				}
			}

			if !found {
				logger.Infof("Creating website...")
				createPayload := websiteCreatePayload{
					Domain: host,
					Name:   ingress.Namespace,
				}
				if title != "" {
					createPayload = websiteCreatePayload{
						Domain: createPayload.Domain,
						Name:   title,
					}
				}
				umamiWebsite, err = apiRequest[websiteCreatePayload, websiteCreateResponse](&umami, "POST", "/api/websites", creds.Token, createPayload)
				if err != nil {
					return fmt.Errorf("while creating new website with %#v: %w", createPayload, err)
				}
			}

			logger.Infof("Using umami website %#v", umamiWebsite)

			var annotationValue bytes.Buffer
			nginxSnippetTemplate.Execute(&annotationValue, umamiWebsite)
			annotations["nginx.ingress.kubernetes.io/configuration-snippet"] = annotationValue.String()

			logger.Infof("Patching ingress annotation: setting configuration snippet to %q", annotationValue.String())

			patch, _ := json.Marshal(&annotationPatch{
				Metadata: struct {
					Annotations map[string]string "json:\"annotations\""
				}{
					Annotations: annotations,
				},
			})
			_, err = k8scli.NetworkingV1().Ingresses(ingress.Namespace).Patch(ctx, ingress.Name, types.MergePatchType, patch, metav1.PatchOptions{})
			if err != nil {
				return fmt.Errorf("while patching ingress: %w", err)
			}
		}

		return nil
	})

	config := &controller.Config{
		Name:      "umami-controller",
		Handler:   handler,
		Retriever: retriever,
		Logger:    logger,

		ProcessingJobRetries: 1,
		ResyncInterval:       60 * time.Second,
		ConcurrentWorkers:    1,
	}

	ctrl, err := controller.New(config)
	if err != nil {
		return fmt.Errorf("could not create controller: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = ctrl.Run(ctx)
	if err != nil {
		return fmt.Errorf("error running controller: %w", err)
	}

	return nil
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error runninng umami controller: %s", err)
		os.Exit(1)
	}

	os.Exit(0)
}
