package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/sirupsen/logrus"
	"github.com/spotahome/kooper/v2/controller"
	kooperlogrus "github.com/spotahome/kooper/v2/log/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
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

const SNIPPET_BEGIN_MARKER = "# Begin Umami snippet"
const SNIPPET_END_MARKER = "# End Umami snippet"

var nginxSnippetTemplate, _ = template.New("nginx snippet").Parse(fmt.Sprintf(`
	%s
	sub_filter "</head>" "<script async src=https://stats.inpt.fr/script.js data-website-id={{ .ID }}></script></head>";
	proxy_set_header Accept-Encoding "";
	%s
`, SNIPPET_BEGIN_MARKER, SNIPPET_END_MARKER))

type annotationPatch struct {
	Metadata struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
}

type websiteInjectConfig struct {
	Inject string
	Name   string
}

type previousWebsiteInjectConfigs map[string]websiteInjectConfig

func run(umami Umami, level logrus.Level) error {
	logconfig := logrus.New()
	logconfig.SetLevel(level)
	logger := kooperlogrus.New(logrus.NewEntry(logconfig))
	k8sconfig, err := rest.InClusterConfig()
	if err != nil {
		// No in cluster? letr's try locally
		kubehome := filepath.Join(homedir.HomeDir(), ".kube", "config")
		k8sconfig, err = clientcmd.BuildConfigFromFlags("", kubehome)
		if err != nil {
			return fmt.Errorf("error loading kubernetes configuration: %w", err)
		}
	}
	latestConfigs := previousWebsiteInjectConfigs{}
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
			logger.Debugf("%s: Skipping resource, no annotation", ingress.Name)
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

		// Check if the ingress has already been processed
		latestConfig := latestConfigs[ingress.Namespace+"/"+ingress.Name]
		if latestConfig.Inject == modeOrHost && latestConfig.Name == title {
			logger.Debugf("%s/%s: Skipping resource, already processed, no changes since %#v", ingress.Namespace, ingress.Name, latestConfig)
			return nil
		}

		latestConfigs[ingress.Namespace+"/"+ingress.Name] = websiteInjectConfig{
			Inject: modeOrHost,
			Name:   title,
		}

		logger.Infof("%s/%s: Injecting in %v (umami.is/inject=%s)", ingress.Namespace, ingress.Name, hosts, modeOrHost)
		annotations := ingress.DeepCopy().Annotations

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

			if title == "" {
				title = cases.Title(language.English).String(ingress.Namespace)
			}

			if !found {
				logger.Infof("Creating website...")
				createPayload := websiteCreatePayload{
					Domain: host,
					Name:   cases.Title(language.English).String(ingress.Namespace),
				}
				umamiWebsite, err = apiRequest[websiteCreatePayload, websiteCreateResponse](&umami, "POST", "/api/websites", creds.Token, createPayload)
				if err != nil {
					return fmt.Errorf("while creating new website with %#v: %w", createPayload, err)
				}
			} else {
				logger.Infof("Updating website...")
				umamiWebsite, err = apiRequest[websiteUpdatePayload, websiteUpdateResponse](&umami, "POST", fmt.Sprintf("/api/websites/%s", umamiWebsite.ID), creds.Token, websiteUpdatePayload{
					Name: title,
					Domain: host,
				})
				if err != nil {
					return fmt.Errorf("while updating website: %w", err)
				}

			}

			logger.Infof("Using umami website %#v", umamiWebsite)

			var annotationValue bytes.Buffer
			nginxSnippetTemplate.Execute(&annotationValue, umamiWebsite)

			// Replace snippet between # Begin Umami snippet and # End Umami snippet
			annotations["nginx.ingress.kubernetes.io/configuration-snippet"] = replaceOrAppend(annotations["nginx.ingress.kubernetes.io/configuration-snippet"], SNIPPET_BEGIN_MARKER, SNIPPET_END_MARKER, annotationValue.String())

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

// replaceOrAppend replaces the content between two strings in a string. If the start or end string is not found, the string is appended to the end.
func replaceOrAppend(s, start, end, replace string) string {
	i := strings.Index(s, start)
	if i == -1 {
		return s + replace
	}
	i += len(start)
	j := strings.Index(s[i:], end)
	if j == -1 {
		return s + replace
	}
	j += i
	return s[:i] + replace + s[j:]
}

func main() {
	umami := Umami{
		Namespace:      os.Getenv("NAMESPACE"),
		AdminSecretRef: os.Getenv("ADMIN_SECRET_REF"),
		Host:           os.Getenv("HOST"),
	}
	fmt.Printf("Starting umami controller with %#v\n", umami)
	err := run(umami, logrus.DebugLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error runninng umami controller: %s", err)
		os.Exit(1)
	}

	os.Exit(0)
}
