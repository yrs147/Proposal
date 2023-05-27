## Personal Information
- **Name** : Yash Raj Singh 
- **Email** : yashraj02.mail@gmail.com
- **Github** : [yrs147](https://github.com/yrs147)
- **LinkedIN** : [y-r-s](https://www.linkedin.com/in/y-r-s/)
- **Resume** : [Link](https://drive.google.com/file/d/1yd5P0jc5VVIRmYHb8He8Jpo0l5GAYtGx/view?usp=sharing)
- **University** : Delhi University
- **Major** : Computer Science
## Project Abstract
Kubescape has a component that runs in-cluster which performs image scanning on all the container images deployed to a cluster. This function is largely used to send the data to an external service. In this projet, you will develop a Prometheus exporter for the image vulnerability information produced by Kubescape. This will allow users to access the data from within the cluster, as well as use it for alerting.
### Expected Outcome 
Implement a Prometheus exporter for Kubescape to access the cluster vulnerability data through it .


## Introduction 
I am a  student at Delhi University, pursuing a major in Computer Science. I am a DevOps Enthusiast and have  proficiency in Golang and Kubernetes. Furthermore, I have been a part of the Kubernetes 1.27 Release Team , where I acquired an in-depth understanding of Kubernetes and its inner workings.
I have worked with Prometheus and Grafana in CI/CD pipelines. In fact, I have even developed a Kubernetes exporter that effectively scrapes Kubernetes metrics, to deepen my knowledge in exporter functionalities [(link)](https://github.com/yrs147/kube-exporter). 
Having closely studied the Kubescape's codebase and successfully setting up the project locally, I am well-versed with its technical nuances. Recognizing the potential of this project, I firmly believe that contributing to the development of a Prometheus exporter for the image vulnerability would be a remarkable opportunity for me to further refine my skills and make meaningful contributions to the Kubescape community.

## Overview 

Kubescape provides support for scanning container images stored within a cluster. Currently, the information about image vulnerabilities can be only accessed on the `ARMO Platform`. However, we aim to enhance its functionality by developing a Prometheus exporter. This exporter will enable the generation of Prometheus metrics from image vulnerability scans, facilitating improved monitoring and observability.

The proposed solution involves building a Prometheus exporter that will scrape the metrics obtained from the image scan. These metrics will then be exposed on a specific endpoint, allowing Prometheus to collect and utilize them for monitoring purposes. By implementing this exporter, users will have the ability to gain valuable insights into the security of their container images and ensure better visibility into any potential vulnerabilities.


### Benefits of the exporter:

1) **Improved Monitoring**: The exporter enables better monitoring capabilities by providing Prometheus metrics specifically tailored to image vulnerability scans. This allows for comprehensive tracking and analysis of security issues within container images.
2) **Enhanced Observability**: With the exporter in place, users gain increased observability into their container images' security posture. They can obtain valuable insights and metrics related to vulnerabilities, enabling proactive measures to address security concerns.
3) **Customizable Metrics**: The exporter allows users to define and customize the specific metrics they want to collect from image vulnerability scans. This flexibility ensures that monitoring aligns with their specific requirements and focuses on the most critical aspects.
4) **Trend Analysis and Historical Data**: By collecting and storing Kubescape's scan metrics over time, Prometheus facilitates trend analysis, historical data comparisons, and the identification of long-term security patterns or improvements.
5) **Integration with Visualization Tools**: Prometheus integrates with visualization tools like Grafana, allowing you to create custom dashboards and reports for monitoring Kubernetes security metrics from Kubescape.


## Proposed Solution 

### What is a Prometheus Exporter? 

A Prometheus exporter is a software component or application that collects specific metrics from a system, service, or application and exposes them in a format that Prometheus can scrape and ingest for monitoring and analysis. By implementing a web server or an HTTP endpoint, the exporter presents the metrics in a Prometheus-compatible format, accompanied by metadata such as labels and descriptions. This allows Prometheus, to periodically scrape the metrics and store them for visualization, alerting, and analysis purposes. Prometheus exporters enable the monitoring of a wide range of systems and applications, providing valuable insights into their performance and facilitating proactive maintenance and issue resolution.

### Prometheus Exporter Architecture

![Screenshot 2023-05-23 173246](https://github.com/yrs147/Proposal/assets/98258627/9fd608d4-1016-4b9f-a53b-9305b057e95b)



This Prometheus Exporter will consist of 3 main files : 

1) `main.go`: This file serves as the entry point of the exporter. It typically includes the necessary package imports and defines the main function. Within the main function, it initializes the necessary components, such as creating a new instance of the Imgstats struct and the Prometheus collector. It also sets up the HTTP server to expose the metrics on the /metrics endpoint. The main.go file acts as the glue code that brings together the different components of the exporter.
```
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	exporter "github.com/yrs147/prometheus-exporter"
)

func main() {
	var (
		targetHost = flag.String("target.host", "localhost", "kubescape address with vulnerability data")
		targetPort = flag.Int("target.port", 8080, "kubescape port with vulnerability data")
		targetPath = flag.String("target.path", "/data", "URL to scrape metrics")
		promPort   = flag.Int("prom.port", 9090"port to expose Prometheus metrics")
	)
	flag.Parse()

	uri := fmt.Sprintf("http://%s:%d%s", *targetHost, *targetPort, *targetPath)

	//called on each collector.Collect
	Stats := func() ([]exporter.ImgStats, error) {
		var netClient = &http.Client{
			Timeout: time.Second * 10,
		}

		resp, err := netClient.Get(uri)
		if err != nil {
			log.Fatal("netClient.Get failed %s: %s", uri, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("io.ReadAll failed: %s", err)
		}
		r := bytes.NewReader(body)

		return exporter.ImgStats(r)
	}

	//Make a Prometheus client aware of our collectors.
	bc := exporter.NewCollector(Stats)

	reg := prometheus.NewRegistry()
	reg.MustRegister(bc)

	mux := http.NewServeMux()
	promHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	mux.Handle("/metrics", promHandler)

	// Start listening for HTTP connections
	port := fmt.Sprintf(":%d", *promPort)
	log.Printf("Starting exporter on %q/metrics", port)
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatalf("Cannot start exporter: %s", err)
	}
}
```
2) `Imgstats.go`: In this file, the metrics struct is defined. The Imgstats struct represents the data received from the scans. It may contain fields such as imageVulnerabilities,Containername , registry , workload , etc. This file defines the struct and its associated methods, allowing for convenient manipulation and conversion of the received data into Prometheus metrics format. The Imgstats struct provides a structured representation of the scan results that can be easily utilized by the exporter.
```
// Will contain the metrics info
type Imgstats struct {
	ContainerName    	string     // Name of the container
	Cluster          	string     // Cluster name
	Namespace        	string     // Namespace of the container
	Workload         	string     // Workload name
	Registry         	string     // Registry name
	ImageTag         	string     // Tag of the container image
	
	TotalVulns       	int        // Total number of vulnerabilities in cluster
	Vulns            	int        // Number of vulnerabilities in image
	TotalImgVulns           int        // Total number of vulnerabilities in image
	TotalCriticalVuns 	int        // Total number of critical vulnerabilities cluster
	CriticalVulns    	int        // Number of critical vulnerabilities in image
	TotalHighVulns          int        // Total number of high vulnerabilities cluster
	HighVulns        	int        // Number of high vulnerabilities in image
	TotalMediumVulns        int        // Total number of medium vulnerabilities cluster
	MediumVulns      	int        // Number of medium vulnerabilities in image
	TotalLowVulns           int        // Total number of low vulnerabilities cluster
	LowVulns        	int        // Number of low vulnerabilities in image
	TotalFixableVulns       int        // Total number of fixable vulnerabilities cluster
	FixableVulns		int        // Number of fixable vulnerabilities in image
	TotalRCEVulns           int        // Total number of vulnerabilities related to remote code execution cluster
	RCEVulns         	int        // Number of vulnerabilities related to remote code execution in image
}

// Code to Convert Scans Results to Prometheus Metrics
  

```
3) `collector.go`: The collector.go file is responsible for defining the metrics using the Prometheus Collector interface. It typically defines the metrics , labels and  implements the required methods: Describe and Collect. The Describe method provides metadata about the metrics, such as their names, help texts, and label configurations. The Collect method gathers the actual metric values from the Imgstats struct or any other relevant data source. It converts these values into Prometheus metric objects and returns them to be scraped by Prometheus. The collector.go file acts as the bridge between the Imgstats struct and the Prometheus library, enabling the exporter to expose the desired metrics.

> Most metrics starting with total prefix will be of Gauge type and the rest will be of GaugeVec Type 

```
import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// CustomCollector collects custom Prometheus metrics.
type CustomCollector struct {
	totalVulnerabilities            prometheus.Gauge
	totalRCEVulnerabilities         prometheus.Gauge
	rceVulnerabilities              prometheus.GaugeVec
	totalFixableVulnerabilities     prometheus.Gauge
	fixableVulnerabilities          prometheus.GaugeVec
	totalImageVulnerabilities       prometheus.GaugeVec
	totalCriticalVulnerabilities    prometheus.Gauge
	criticalVulnerabilities         prometheus.GaugeVec
	totalHighVulnerabilities        prometheus.Gauge
	highVulnerabilities             prometheus.GaugeVec
	totalMediumVulnerabilities      prometheus.Gauge
	mediumVulnerabilities           prometheus.GaugeVec
	totalLowVulnerabilities         prometheus.Gauge
	lowVulnerabilities              prometheus.GaugeVec
	totalNegligibleVulnerabilities  prometheus.Gauge
	negligibleVulnerabilities       prometheus.GaugeVec
	totalUnknownVulnerabilities     prometheus.Gauge
	unknownVulnerabilities          prometheus.GaugeVec
}

// NewCustomCollector creates a new instance of CustomCollector and initializes the metrics.
func NewCustomCollector() *CustomCollector {
	return &CustomCollector{
		totalVulnerabilities: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "total_vulnerabilities",
			Help: "Total number of vulnerabilities in cluster",
		}),
		totalRCEVulnerabilities: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "total_rce_vulnerabilities",
			Help: "Total number of vulnerabilities related to remote code execution (RCE) in cluster",
		},
		rceVulnerabilities: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "rce_vulnerabilities",
			Help: "Number of vulnerabilities related to remote code execution (RCE) in image",
		}, []string{"name", "cluster", "namespace", "workload","registry","tag"}),
		totalFixableVulnerabilities: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "total_fixable_vulnerabilities",
			Help: "Total number of fixable vulnerabilities in cluster",
		}),
		fixableVulnerabilities: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "fixable_vulnerabilities",
			Help: "Number of fixable vulnerabilities in image",
		}, []string{"name", "cluster", "namespace", "workload","registry","tag"}),
		totalImageVulnerabilities: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "total_image_vulnerabilities",
			Help: "Total number of vulnerabilities in image",
		}, []string{"name", "cluster", "namespace", "workload","registry","tag"}),
		totalCriticalVulnerabilities: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "total_critical_vulnerabilities",
			Help: "Total number of critical vulnerabilities in cluster",
		}),
		criticalVulnerabilities: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "critical_vulnerabilities",
			Help: "Number of critical vulnerabilities in image",
		}, []string{"name", "cluster", "namespace", "workload","registry","tag"}),
		totalHighVulnerabilities: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "total_high_vulnerabilities",
			Help: "Total number of high vulnerabilities in cluster",
		}),
		highVulnerabilities: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "high_vulnerabilities",
			Help: "Number of high vulnerabilities in image",
		}, []string{"name", "cluster", "namespace", "workload","registry","tag"}),
		totalMediumVulnerabilities: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "total_medium_vulnerabilities",
			Help: "Total number of medium vulnerabilities in cluster",
		}),
		mediumVulnerabilities: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "medium_vulnerabilities",
			Help: "Number of medium vulnerabilities in image",
		}, []string{"name", "cluster", "namespace", "workload","registry","tag"}),
		totalLowVulnerabilities: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "total_low_vulnerabilities",
			Help: "Total number of low vulnerabilities in cluster",
		}),
		lowVulnerabilities: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "low_vulnerabilities",
			Help: "Number of low vulnerabilities in image",
		}, []string{"name", "cluster", "namespace", "workload","registry","tag"}),
		totalNegligibleVulnerabilities: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "total_negligible_vulnerabilities",
			Help: "Total number of negligible vulnerabilities in cluster",
		}),
		negligibleVulnerabilities: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "negligible_vulnerabilities",
			Help: "Number of negligible vulnerabilities in image",
		}, []string{"name", "cluster", "namespace", "workload","registry","tag"}),
		totalUnknownVulnerabilities: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "total_unknown_vulnerabilities",
			Help: "Total number of unknown vulnerabilities in cluster",
		}),
		unknownVulnerabilities: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "unknown_vulnerabilities",
			Help: "Number of unknown vulnerabilities in image",
		}, []string{"name", "cluster", "namespace", "workload","registry","tag"}),
	}
}


// Describe sends the descriptors of the metrics to the provided channel.
func (c *CustomCollector) Describe(ch chan<- *prometheus.Desc) {
	c.totalVulnerabilities.Describe(ch)
	c.totalRCEVulnerabilities.Describe(ch)
	c.rceVulnerabilities.Describe(ch)
	c.totalFixableVulnerabilities.Describe(ch)
	c.fixableVulnerabilities.Describe(ch)
	c.totalImageVulnerabilities.Describe(ch)
	c.totalCriticalVulnerabilities.Describe(ch)
	c.criticalVulnerabilities.Describe(ch)
	c.totalHighVulnerabilities.Describe(ch)
	c.highVulnerabilities.Describe(ch)
	c.totalMediumVulnerabilities.Describe(ch)
	c.mediumVulnerabilities.Describe(ch)
	c.totalLowVulnerabilities.Describe(ch)
	c.lowVulnerabilities.Describe(ch)
	c.totalNegligibleVulnerabilities.Describe(ch)
	c.negligibleVulnerabilities.Describe(ch)
	c.totalUnknownVulnerabilities.Describe(ch)
	c.unknownVulnerabilities.Describe(ch)
}

// Collect sends the metric values to the provided channel.
func (c *CustomCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- c.totalVulnerabilities(ch)
	ch <- c.totalRCEVulnerabilities(ch)
	ch <- c.totalFixableVulnerabilities(ch)
	ch <- c.totalCriticalVulnerabilities(ch)
	ch <- c.totalHighVulnerabilities(ch)
	ch <- c.totalMediumVulnerabilities(ch)
	ch <- c.totalLowVulnerabilities(ch)
	ch <- c.totalNegligibleVulnerabilities(ch)
	ch <- c.totalUnknownVulnerabilities(ch)

	ch <- c.rceVulnerabilities.Collect(ch)
	ch <- c.fixableVulnerabilities.Collect(ch)
	ch <- c.totalImageVulnerabilities.Collect(ch)
	ch <- ch <- c.criticalVulnerabilities.Collect(ch)
	ch <- c.highVulnerabilities.Collect(ch)
	ch <- c.mediumVulnerabilities.Collect(ch)
	ch <- c.lowVulnerabilities.Collect(ch)
	ch <- c.negligibleVulnerabilities.Collect(ch)
	ch <- c.unknownVulnerabilities.Collect(ch)
}
	

}
```

### File Structure
```
exporter/
├── main.go
├── imgstats.go
├── collector.go
```


### Metics Definition

![Screenshot 2023-05-24 184533](https://github.com/yrs147/Proposal/assets/98258627/fc86312e-f485-4d19-a634-ed78c36fe283)



These are the metrics which exporter will scrape :- 
1) `total_vulnerabilities`: Total Number of vulnerabilities in cluster. (Gauge)
2) `total_rce_vulnerabilities`: Total Number of vulnerabilities related to remote code execution in cluster. (Gauge)
3) `rce_vulnerabilities`: Number of vulnerabilities related to remote code execution in image. (GaugeVec)
4) `total_fixable_vulnerabilities`: Total Number of fixable vulnerabilites in cluster. (Gauge)
5) `fixable_vulnerabilities`: Number of fixable vulnerabilites in image .  (Gauge)
6) `total_image_vulnerabilities`: Total Number of vulnerabilities in image . (GaugeVec)
7) `total_critical_vulnerabilities`: Total Number of critical vulnerabilities in cluster . (Gauge)
8) `critical_vulnerabilities`: Number of critical vulnerabilities in image. (GaugeVec)
9) `total_high_vulnerabilities`: Total Number of high vulnerabilities in cluster. (Gauge)
10) `high_vulnerabilities`: Number of high vulnerabilities in image. (GaugeVec)
11) `total_medium_vulnerabilities`: Total Number of medium vulnerabilities in cluster. (Gauge)
12) `medium_vulnerabilities`: Number of medium vulnerabilities in image. (GaugeVec)
13) `total_low_vulnerabilities`: Total Number of low vulnerabilities in cluster. (Gauge)
14) `low_vulnerabilities`: Number of low vulnerabilities in image. (GaugeVec)
15) `total_negligible_vulnerabilities`: Total Number of negligible vulnerabilities in cluster. (Gauge)
16) `negligible_vulnerabilities`: Number of negligible vulnerabilities in image. (GaugeVec)
17) `total_unknown_vulnerabilities`: Total Number of unknown vulnerabilities in cluster. (Gauge)
18) `unknown_vulnerabilities`: Number of unknown vulnerabilities in image. (GaugeVec)

### Labels 
1) `Name`: The name of the container.
2) `Cluster`: The name of the cluster where the image is deployed.
3) `Namespace`: The namespace in which the image is running.
4) `Workload`: The type of workload associated with the image.
5) `Registry`: The registry where the image is stored.
6) `Tag`: The tag of the image.

## Related Prometheus Exporters for Reference (Further Research To Be Done)

Prometheus exporters that can provide valuable insights and inspiration for the development of the Kubescape Prometheus exporter for Image Vulnerabilities: 
1.  [blackbox_exporter](https://github.com/prometheus/blackbox_exporter): The Blackbox Exporter is designed to probe endpoints over different protocols (HTTP, HTTPS, ICMP, DNS) and collect metrics about their availability, response times, and other relevant information. It is commonly used for monitoring external services and network connectivity. Exploring the Blackbox Exporter can provide valuable guidance on how to implement an exporter that performs specific checks or probes against external services. It showcases how to define and structure metrics related to probing, handle various types of checks, and expose the collected data in a Prometheus-compatible format.

2.  [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics): The kube-state-metrics exporter collects and exposes metrics about the state of Kubernetes objects, such as pods, deployments, services, and nodes. It provides valuable insights into the health and status of the Kubernetes cluster. Studying the kube-state-metrics exporter can offer inspiration for designing and implementing metrics related to Kubernetes-specific components in the Kubescape Prometheus exporter. It demonstrates how to structure and expose metrics for various Kubernetes resources and how to handle the dynamic nature of the cluster.    
3.  [DockerHub-exporter](https://github.com/infinityworks/docker-hub-exporter): With DockerHub exporter, we can understand the methodologies and techniques for extracting relevant information from image registries like DockerHub, such as image metadata, vulnerability details, and other metrics. We can gain insights into the API endpoints, authentication mechanisms, and data structures specific to different image registries. This knowledge can be applied in the our Prometheus exporter to fetch image vulnerability data from various registries and process it into prometheus metrics ensuring optimal performance and reliability for our Prometheus exporter. 
