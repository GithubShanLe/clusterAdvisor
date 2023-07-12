package main

import (
	"clusterAdvision/pkg/conf"
	"context"
	"fmt"

	"clusterAdvision/pkg/client"

	_ "github.com/go-sql-driver/mysql"
)

type AuditResults struct {
	NameSpace   string        `json:"namespace,omitempty"`
	ResultInfos []ResultInfos `json:"resultInfos,omitempty"`
}

type ResultInfos struct {
	ResourceType  string `json:"resourceType,omitempty"`
	ResourceInfos `json:"resourceInfos,omitempty"`
}

type ResourceInfos struct {
	Name        string        `json:"name,omitempty"`
	ResultItems []ResultItems `json:"items,omitempty"`
}

type ResultItems struct {
	Level   string `json:"level,omitempty"`
	Message string `json:"message,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// kubeconfig content
var kubeconfig string = ``

func main() {

	var k8sClient = new(client.KubernetesClient)
	client, err := k8sClient.NewKubernetesClient(kubeconfig)
	if err != nil {
		panic(err)
	}
	for _, reourceTypeItem := range []string{conf.Pods, conf.Events} {
		resource, err := client.GetK8SResourcesProvider(context.Background(), reourceTypeItem)
		if err != nil {
			fmt.Println(reourceTypeItem, err)
			continue
		}
		fmt.Println(resource)
	}

}
