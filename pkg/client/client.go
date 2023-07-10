package client

import (
	"clusterAdvision/pkg/conf"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KubernetesClient struct {
	KubeConfig    *rest.Config
	ClientSet     kubernetes.Interface
	DynamicClient dynamic.Interface
}

type ValidateResult struct {
	Name      string
	Namespace string
	Type      string
	Level     string
	Message   string
	Reason    string
	EventTime int64
}

func (k *KubernetesClient) NewKubernetesClient(kubeconfig string) (*KubernetesClient, error) {

	kubeConfig, err := GetKubeConfig(kubeconfig)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load config file")
	}

	clientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load clientSet")
	}

	dynamicClient, err := dynamic.NewForConfig(kubeConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load dynamicClient")
	}

	k.ClientSet = clientSet
	k.DynamicClient = dynamicClient
	k.KubeConfig = kubeConfig
	return k, nil
}

func GetKubeConfig(kubeconfig string) (*rest.Config, error) {
	return clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfig))
}

func (k *KubernetesClient) GetK8SResourcesProvider(ctx context.Context, resourceType string) ([]ValidateResult, error) {

	var validateResult []ValidateResult
	switch resourceType {
	case conf.Pods:
		resource, err := k.ClientSet.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, item := range resource.Items {
			restartCount := 0
			for _, v := range item.Status.ContainerStatuses {
				restartCount += int(v.RestartCount)
			}
			if restartCount != 0 {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Pods,
					Message:   "Pod Restart",
					Level:     fmt.Sprintf("%d", restartCount),
				})
			}
			var (
				ready   = true
				message string
				reason  string
			)
			for _, v := range item.Status.ContainerStatuses {
				if !v.Ready {
					if v.State.Waiting != nil {
						ready = v.Ready
						message = v.State.Waiting.Reason
						reason = item.Status.Message
					}
					if v.State.Terminated != nil {
						ready = v.Ready
						message = v.State.Terminated.Reason
						reason = item.Status.Message
					}
					break
				}
			}
			if !ready {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Pods,
					Message:   message,
					Level:     reason,
				})
			}

		}
	case conf.Deployments:
		resource, err := k.ClientSet.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, item := range resource.Items {
			if item.Spec.Replicas == nil || *item.Spec.Replicas < 2 {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Deployments,
					Message:   "replicas less 2",
					Reason:    fmt.Sprintf("%d", *item.Spec.Replicas),
					Level:     "danger",
				})
			}
			if item.Spec.Template.Spec.HostIPC {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Deployments,
					Message:   "HostIPCAllowed",
					Level:     "danger",
				})
			}
			if item.Spec.Template.Spec.HostNetwork {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Deployments,
					Message:   "HostNetworkAllowed",
					Level:     "danger",
				})
			}

			if item.Spec.Template.Spec.HostPID {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Deployments,
					Message:   "HostPIDAllowed",
					Level:     "danger",
				})
			}

			if item.Spec.Template.Spec.PriorityClassName == "" {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Deployments,
					Message:   "NoPriorityClassName",
					Level:     "ignore",
				})
			}

			var (
				flagCpuLimit                  bool
				flagCpuRequest                bool
				flagMemLimit                  bool
				flagMemRequest                bool
				flagHostPort                  bool
				flagImagePull                 bool
				flagImageTagMiss              bool
				flagImageTagLatest            bool
				flagLivenessProbe             bool
				flagReadnessProbe             bool
				flagPrivilegedAllowed         bool
				flagNotReadOnlyRootFilesystem bool
				flagNotRunAsNonRoot           bool
			)
			if item.Spec.Template.Spec.SecurityContext != nil && item.Spec.Template.Spec.SecurityContext.RunAsNonRoot != nil && *item.Spec.Template.Spec.SecurityContext.RunAsNonRoot {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Deployments,
					Message:   "NotRunAsNonRoot",
					Level:     "danger",
				})
				flagNotRunAsNonRoot = true
			}
			// if item.Spec.Template.Spec.SecurityContext != nil && item.Spec.Template.Spec.SecurityContext.RunAsNonRoot != nil && *item.Spec.Template.Spec.SecurityContext.RunAsNonRoot {
			// 	validateResult = append(validateResult, ValidateResult{
			// 		Name:      item.Name,
			// 		Namespace: item.Namespace,
			// 		Type:      conf.Deployments,
			// 		Message:   "NotRunAsNonRoot",
			// 		Level:     "danger",
			// 	})
			// 	flagNotRunAsNonRoot = true
			// }
			for _, container := range item.Spec.Template.Spec.Containers {
				if !flagCpuLimit && (container.Resources.Limits.Cpu() == nil || container.Resources.Limits.Cpu().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "NoCPULimits",
						Level:     "danger",
					})
					flagCpuLimit = true
				}

				if !flagCpuRequest && (container.Resources.Requests.Cpu() == nil || container.Resources.Requests.Cpu().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "NoCPURequests",
						Level:     "danger",
					})
					flagCpuRequest = true
				}

				if !flagMemLimit && (container.Resources.Limits.Memory() == nil || container.Resources.Limits.Memory().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "NoMemoryLimits",
						Level:     "danger",
					})
					flagMemLimit = true
				}

				if !flagMemRequest && (container.Resources.Requests.Memory() == nil || container.Resources.Requests.Memory().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "NoMemoryRequest",
						Level:     "danger",
					})
					flagMemRequest = true
				}

				// if container.SecurityContext != nil && reflect.DeepEqual(container.SecurityContext.Capabilities.Add, []corev1.Capability{"NET_ADMIN", "SYS_ADMIN", "ALL"}) {
				// 	validateResult = append(validateResult, ValidateResult{
				// 		Name:      item.Name,
				// 		Namespace: item.Namespace,
				// 		Type:      conf.Deployments,
				// 		Message:   "HighRiskCapabilities",
				// 		Level:     "danger",
				// 	})
				// }
				for _, portItem := range container.Ports {
					if !flagHostPort && portItem.HostPort > 0 {
						validateResult = append(validateResult, ValidateResult{
							Name:      item.Name,
							Namespace: item.Namespace,
							Type:      conf.Deployments,
							Message:   "HostPortAllowed",
							Level:     "danger",
						})
						flagHostPort = true
					}
				}

				if !flagImagePull && container.ImagePullPolicy != "Always" {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "ImagePullPolicyNotAlways",
						Level:     "warning",
					})
					flagImagePull = true
				}
				flag, _ := regexp.Match("^.+:.+$", []byte(container.Image))
				if !flag && !flagImageTagMiss {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "ImageTagMiss",
						Level:     "danger",
					})
					flagImageTagMiss = true
				}

				flag, _ = regexp.Match("^.+:latest$", []byte(container.Image))

				if flag && !flagImageTagLatest {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "ImageTagIsLatest",
						Level:     "danger",
					})
					flagImageTagLatest = true
				}

				// if container.SecurityContext != nil && reflect.DeepEqual(container.SecurityContext.Capabilities.Add, []corev1.Capability{"CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID", "SETFCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"}) {
				// 	validateResult = append(validateResult, ValidateResult{
				// 		Name:      item.Name,
				// 		Namespace: item.Namespace,
				// 		Type:      conf.Deployments,
				// 		Message:   "InsecureCapabilities",
				// 		Level:     "danger",
				// 	})
				// }
				if !flagLivenessProbe && container.LivenessProbe == nil {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "NoLivenessProbe",
						Level:     "warning",
					})
					flagLivenessProbe = true
				}
				if !flagReadnessProbe && container.ReadinessProbe == nil {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "NoReadinessProbe",
						Level:     "warning",
					})
					flagReadnessProbe = true
				}
				if !flagPrivilegedAllowed && (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "PrivilegedAllowed",
						Level:     "danger",
					})
					flagPrivilegedAllowed = true
				}
				if !flagNotReadOnlyRootFilesystem && (container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "NotReadOnlyRootFilesystem",
						Level:     "danger",
					})
					flagNotReadOnlyRootFilesystem = true
				}

				if !flagNotRunAsNonRoot && (container.SecurityContext != nil && container.SecurityContext.RunAsNonRoot != nil && *container.SecurityContext.RunAsNonRoot) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Deployments,
						Message:   "NotRunAsNonRoot",
						Level:     "danger",
					})
					flagNotRunAsNonRoot = true
				}
			}
		}
	case conf.Cronjobs:
		resource, err := k.ClientSet.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, item := range resource.Items {
			if item.Spec.JobTemplate.Spec.Template.Spec.HostIPC {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Cronjobs,
					Message:   "HostIPCAllowed",
					Level:     "danger",
				})
			}
			if item.Spec.JobTemplate.Spec.Template.Spec.HostNetwork {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Cronjobs,
					Message:   "HostNetworkAllowed",
					Level:     "danger",
				})
			}

			if item.Spec.JobTemplate.Spec.Template.Spec.HostPID {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Cronjobs,
					Message:   "HostPIDAllowed",
					Level:     "danger",
				})
			}

			if item.Spec.JobTemplate.Spec.Template.Spec.PriorityClassName == "" {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Cronjobs,
					Message:   "NoPriorityClassName",
					Level:     "ignore",
				})
			}

			var (
				flagCpuLimit                  bool
				flagCpuRequest                bool
				flagMemLimit                  bool
				flagMemRequest                bool
				flagHostPort                  bool
				flagImagePull                 bool
				flagImageTagMiss              bool
				flagImageTagLatest            bool
				flagLivenessProbe             bool
				flagReadnessProbe             bool
				flagPrivilegedAllowed         bool
				flagNotReadOnlyRootFilesystem bool
				flagNotRunAsNonRoot           bool
			)

			if item.Spec.JobTemplate.Spec.Template.Spec.SecurityContext != nil && item.Spec.JobTemplate.Spec.Template.Spec.SecurityContext.RunAsNonRoot != nil && *item.Spec.JobTemplate.Spec.Template.Spec.SecurityContext.RunAsNonRoot {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Statefulsets,
					Message:   "NotRunAsNonRoot",
					Level:     "danger",
				})
				flagNotRunAsNonRoot = true
			}

			for _, container := range item.Spec.JobTemplate.Spec.Template.Spec.Containers {
				if !flagCpuLimit && (container.Resources.Limits.Cpu() == nil || container.Resources.Limits.Cpu().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "NoCPULimits",
						Level:     "danger",
					})
					flagCpuLimit = true
				}

				if !flagCpuRequest && (container.Resources.Requests.Cpu() == nil || container.Resources.Requests.Cpu().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "NoCPURequests",
						Level:     "danger",
					})
					flagCpuRequest = true
				}

				if !flagMemLimit && (container.Resources.Limits.Memory() == nil || container.Resources.Limits.Memory().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "NoMemoryLimits",
						Level:     "danger",
					})
					flagMemLimit = true
				}

				if !flagMemRequest && (container.Resources.Requests.Memory() == nil || container.Resources.Requests.Memory().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "NoMemoryRequest",
						Level:     "danger",
					})
					flagMemRequest = true
				}

				// if container.SecurityContext != nil && reflect.DeepEqual(container.SecurityContext.Capabilities.Add, []corev1.Capability{"NET_ADMIN", "SYS_ADMIN", "ALL"}) {
				// 	validateResult = append(validateResult, ValidateResult{
				// 		Name:      item.Name,
				// 		Namespace: item.Namespace,
				// 		Type:      conf.Cronjobs,
				// 		Message:   "HighRiskCapabilities",
				// 		Level:     "danger",
				// 	})
				// }
				for _, portItem := range container.Ports {
					if !flagHostPort && portItem.HostPort > 0 {
						validateResult = append(validateResult, ValidateResult{
							Name:      item.Name,
							Namespace: item.Namespace,
							Type:      conf.Cronjobs,
							Message:   "HostPortAllowed",
							Level:     "danger",
						})
						flagHostPort = true
					}
				}

				if !flagImagePull && container.ImagePullPolicy != "Always" {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "ImagePullPolicyNotAlways",
						Level:     "warning",
					})
					flagImagePull = true
				}
				flag, _ := regexp.Match("^.+:.+$", []byte(container.Image))
				if !flag && !flagImageTagMiss {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "ImageTagMiss",
						Level:     "danger",
					})
					flagImageTagMiss = true
				}

				flag, _ = regexp.Match("^.+:latest$", []byte(container.Image))

				if flag && !flagImageTagLatest {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "ImageTagIsLatest",
						Level:     "danger",
					})
					flagImageTagLatest = true
				}

				// if container.SecurityContext != nil && reflect.DeepEqual(container.SecurityContext.Capabilities.Add, []corev1.Capability{"CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID", "SETFCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"}) {
				// 	validateResult = append(validateResult, ValidateResult{
				// 		Name:      item.Name,
				// 		Namespace: item.Namespace,
				// 		Type:      conf.Cronjobs,
				// 		Message:   "InsecureCapabilities",
				// 		Level:     "danger",
				// 	})
				// }
				if !flagLivenessProbe && container.LivenessProbe == nil {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "NoLivenessProbe",
						Level:     "warning",
					})
					flagLivenessProbe = true
				}
				if !flagReadnessProbe && container.ReadinessProbe == nil {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "NoReadinessProbe",
						Level:     "warning",
					})
					flagReadnessProbe = true
				}
				if !flagPrivilegedAllowed && (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "PrivilegedAllowed",
						Level:     "danger",
					})
					flagPrivilegedAllowed = true
				}
				if !flagNotReadOnlyRootFilesystem && (container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "NotReadOnlyRootFilesystem",
						Level:     "danger",
					})
					flagNotReadOnlyRootFilesystem = true
				}

				if !flagNotRunAsNonRoot && (container.SecurityContext != nil && container.SecurityContext.RunAsNonRoot != nil && *container.SecurityContext.RunAsNonRoot) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Cronjobs,
						Message:   "NotRunAsNonRoot",
						Level:     "danger",
					})
					flagNotRunAsNonRoot = true
				}
			}
		}
	case conf.Statefulsets:
		resource, err := k.ClientSet.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, item := range resource.Items {
			if item.Spec.Replicas == nil || *item.Spec.Replicas < 2 {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Statefulsets,
					Message:   "replicas less 2",
					Level:     "danger",
					Reason:    fmt.Sprintf("%d", *item.Spec.Replicas),
				})
			}
			if item.Spec.Template.Spec.HostIPC {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Statefulsets,
					Message:   "HostIPCAllowed",
					Level:     "danger",
				})
			}
			if item.Spec.Template.Spec.HostNetwork {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Statefulsets,
					Message:   "HostNetworkAllowed",
					Level:     "danger",
				})
			}

			if item.Spec.Template.Spec.HostPID {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Statefulsets,
					Message:   "HostPIDAllowed",
					Level:     "danger",
				})
			}

			if item.Spec.Template.Spec.PriorityClassName == "" {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Statefulsets,
					Message:   "NoPriorityClassName",
					Level:     "ignore",
				})
			}

			var (
				flagCpuLimit                  bool
				flagCpuRequest                bool
				flagMemLimit                  bool
				flagMemRequest                bool
				flagHostPort                  bool
				flagImagePull                 bool
				flagImageTagMiss              bool
				flagImageTagLatest            bool
				flagLivenessProbe             bool
				flagReadnessProbe             bool
				flagPrivilegedAllowed         bool
				flagNotReadOnlyRootFilesystem bool
				flagNotRunAsNonRoot           bool
			)
			if item.Spec.Template.Spec.SecurityContext != nil && item.Spec.Template.Spec.SecurityContext.RunAsNonRoot != nil && *item.Spec.Template.Spec.SecurityContext.RunAsNonRoot {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Statefulsets,
					Message:   "NotRunAsNonRoot",
					Level:     "danger",
				})
				flagNotRunAsNonRoot = true
			}

			for _, container := range item.Spec.Template.Spec.Containers {
				if !flagCpuLimit && (container.Resources.Limits.Cpu() == nil || container.Resources.Limits.Cpu().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "NoCPULimits",
						Level:     "danger",
					})
					flagCpuLimit = true
				}

				if !flagCpuRequest && (container.Resources.Requests.Cpu() == nil || container.Resources.Requests.Cpu().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "NoCPURequests",
						Level:     "danger",
					})
					flagCpuRequest = true
				}

				if !flagMemLimit && (container.Resources.Limits.Memory() == nil || container.Resources.Limits.Memory().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "NoMemoryLimits",
						Level:     "danger",
					})
					flagMemLimit = true
				}

				if !flagMemRequest && (container.Resources.Requests.Memory() == nil || container.Resources.Requests.Memory().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "NoMemoryRequest",
						Level:     "danger",
					})
					flagMemRequest = true
				}

				// if container.SecurityContext != nil && reflect.DeepEqual(container.SecurityContext.Capabilities.Add, []corev1.Capability{"NET_ADMIN", "SYS_ADMIN", "ALL"}) {
				// 	validateResult = append(validateResult, ValidateResult{
				// 		Name:      item.Name,
				// 		Namespace: item.Namespace,
				// 		Type:      conf.Statefulsets,
				// 		Message:   "HighRiskCapabilities",
				// 		Level:     "danger",
				// 	})
				// }
				for _, portItem := range container.Ports {
					if !flagHostPort && portItem.HostPort > 0 {
						validateResult = append(validateResult, ValidateResult{
							Name:      item.Name,
							Namespace: item.Namespace,
							Type:      conf.Statefulsets,
							Message:   "HostPortAllowed",
							Level:     "danger",
						})
						flagHostPort = true
					}
				}

				if !flagImagePull && container.ImagePullPolicy != "Always" {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "ImagePullPolicyNotAlways",
						Level:     "warning",
					})
					flagImagePull = true
				}
				flag, _ := regexp.Match("^.+:.+$", []byte(container.Image))
				if !flag && !flagImageTagMiss {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "ImageTagMiss",
						Level:     "danger",
					})
					flagImageTagMiss = true
				}

				flag, _ = regexp.Match("^.+:latest$", []byte(container.Image))

				if flag && !flagImageTagLatest {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "ImageTagIsLatest",
						Level:     "danger",
					})
					flagImageTagLatest = true
				}

				// if container.SecurityContext != nil && reflect.DeepEqual(container.SecurityContext.Capabilities.Add, []corev1.Capability{"CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID", "SETFCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"}) {
				// 	validateResult = append(validateResult, ValidateResult{
				// 		Name:      item.Name,
				// 		Namespace: item.Namespace,
				// 		Type:      conf.Statefulsets,
				// 		Message:   "InsecureCapabilities",
				// 		Level:     "danger",
				// 	})
				// }
				if !flagLivenessProbe && container.LivenessProbe == nil {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "NoLivenessProbe",
						Level:     "warning",
					})
					flagLivenessProbe = true
				}
				if !flagReadnessProbe && container.ReadinessProbe == nil {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "NoReadinessProbe",
						Level:     "warning",
					})
					flagReadnessProbe = true
				}
				if !flagPrivilegedAllowed && (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "PrivilegedAllowed",
						Level:     "danger",
					})
					flagPrivilegedAllowed = true
				}
				if !flagNotReadOnlyRootFilesystem && (container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "NotReadOnlyRootFilesystem",
						Level:     "danger",
					})
					flagNotReadOnlyRootFilesystem = true
				}

				if !flagNotRunAsNonRoot && (container.SecurityContext != nil && container.SecurityContext.RunAsNonRoot != nil && *container.SecurityContext.RunAsNonRoot) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Statefulsets,
						Message:   "NotRunAsNonRoot",
						Level:     "danger",
					})
					flagNotRunAsNonRoot = true
				}
			}
		}
	case conf.Jobs:
		resource, err := k.ClientSet.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, item := range resource.Items {
			if item.Spec.Template.Spec.HostIPC {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Jobs,
					Message:   "HostIPCAllowed",
					Level:     "danger",
				})
			}
			if item.Spec.Template.Spec.HostNetwork {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Jobs,
					Message:   "HostNetworkAllowed",
					Level:     "danger",
				})
			}

			if item.Spec.Template.Spec.HostPID {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Jobs,
					Message:   "HostPIDAllowed",
					Level:     "danger",
				})
			}

			if item.Spec.Template.Spec.PriorityClassName == "" {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Jobs,
					Message:   "NoPriorityClassName",
					Level:     "ignore",
				})
			}

			var (
				flagCpuLimit                  bool
				flagCpuRequest                bool
				flagMemLimit                  bool
				flagMemRequest                bool
				flagHostPort                  bool
				flagImagePull                 bool
				flagImageTagMiss              bool
				flagImageTagLatest            bool
				flagLivenessProbe             bool
				flagReadnessProbe             bool
				flagPrivilegedAllowed         bool
				flagNotReadOnlyRootFilesystem bool
				flagNotRunAsNonRoot           bool
			)
			if item.Spec.Template.Spec.SecurityContext != nil && item.Spec.Template.Spec.SecurityContext.RunAsNonRoot != nil && *item.Spec.Template.Spec.SecurityContext.RunAsNonRoot {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Jobs,
					Message:   "NotRunAsNonRoot",
					Level:     "danger",
				})
				flagNotRunAsNonRoot = true
			}
			for _, container := range item.Spec.Template.Spec.Containers {
				if !flagCpuLimit && (container.Resources.Limits.Cpu() == nil || container.Resources.Limits.Cpu().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "NoCPULimits",
						Level:     "danger",
					})
					flagCpuLimit = true
				}

				if !flagCpuRequest && (container.Resources.Requests.Cpu() == nil || container.Resources.Requests.Cpu().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "NoCPURequests",
						Level:     "danger",
					})
					flagCpuRequest = true
				}

				if !flagMemLimit && (container.Resources.Limits.Memory() == nil || container.Resources.Limits.Memory().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "NoMemoryLimits",
						Level:     "danger",
					})
					flagMemLimit = true
				}

				if !flagMemRequest && (container.Resources.Requests.Memory() == nil || container.Resources.Requests.Memory().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "NoMemoryRequest",
						Level:     "danger",
					})
					flagMemRequest = true
				}

				// if container.SecurityContext != nil && reflect.DeepEqual(container.SecurityContext.Capabilities.Add, []corev1.Capability{"NET_ADMIN", "SYS_ADMIN", "ALL"}) {
				// 	validateResult = append(validateResult, ValidateResult{
				// 		Name:      item.Name,
				// 		Namespace: item.Namespace,
				// 		Type:      conf.Jobs,
				// 		Message:   "HighRiskCapabilities",
				// 		Level:     "danger",
				// 	})
				// }
				for _, portItem := range container.Ports {
					if !flagHostPort && portItem.HostPort > 0 {
						validateResult = append(validateResult, ValidateResult{
							Name:      item.Name,
							Namespace: item.Namespace,
							Type:      conf.Jobs,
							Message:   "HostPortAllowed",
							Level:     "danger",
						})
						flagHostPort = true
					}
				}

				if !flagImagePull && container.ImagePullPolicy != "Always" {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "ImagePullPolicyNotAlways",
						Level:     "warning",
					})
					flagImagePull = true
				}
				flag, _ := regexp.Match("^.+:.+$", []byte(container.Image))
				if !flag && !flagImageTagMiss {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "ImageTagMiss",
						Level:     "danger",
					})
					flagImageTagMiss = true
				}

				flag, _ = regexp.Match("^.+:latest$", []byte(container.Image))

				if flag && !flagImageTagLatest {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "ImageTagIsLatest",
						Level:     "danger",
					})
					flagImageTagLatest = true
				}

				// if container.SecurityContext != nil && reflect.DeepEqual(container.SecurityContext.Capabilities.Add, []corev1.Capability{"CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID", "SETFCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"}) {
				// 	validateResult = append(validateResult, ValidateResult{
				// 		Name:      item.Name,
				// 		Namespace: item.Namespace,
				// 		Type:      conf.Jobs,
				// 		Message:   "InsecureCapabilities",
				// 		Level:     "danger",
				// 	})
				// }
				if !flagLivenessProbe && container.LivenessProbe == nil {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "NoLivenessProbe",
						Level:     "warning",
					})
					flagLivenessProbe = true
				}
				if !flagReadnessProbe && container.ReadinessProbe == nil {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "NoReadinessProbe",
						Level:     "warning",
					})
					flagReadnessProbe = true
				}
				if !flagPrivilegedAllowed && (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "PrivilegedAllowed",
						Level:     "danger",
					})
					flagPrivilegedAllowed = true
				}
				if !flagNotReadOnlyRootFilesystem && (container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "NotReadOnlyRootFilesystem",
						Level:     "danger",
					})
					flagNotReadOnlyRootFilesystem = true
				}

				if !flagNotRunAsNonRoot && (container.SecurityContext != nil && container.SecurityContext.RunAsNonRoot != nil && *container.SecurityContext.RunAsNonRoot) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Jobs,
						Message:   "NotRunAsNonRoot",
						Level:     "danger",
					})
					flagNotRunAsNonRoot = true
				}
			}
		}
	case conf.Daemonsets:
		resource, err := k.ClientSet.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, item := range resource.Items {
			if item.Spec.Template.Spec.HostIPC {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Daemonsets,
					Message:   "HostIPCAllowed",
					Level:     "danger",
				})
			}
			if item.Spec.Template.Spec.HostNetwork {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Daemonsets,
					Message:   "HostNetworkAllowed",
					Level:     "danger",
				})
			}

			if item.Spec.Template.Spec.HostPID {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Daemonsets,
					Message:   "HostPIDAllowed",
					Level:     "danger",
				})
			}

			if item.Spec.Template.Spec.PriorityClassName == "" {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Daemonsets,
					Message:   "NoPriorityClassName",
					Level:     "ignore",
				})
			}

			var (
				flagCpuLimit                  bool
				flagCpuRequest                bool
				flagMemLimit                  bool
				flagMemRequest                bool
				flagHostPort                  bool
				flagImagePull                 bool
				flagImageTagMiss              bool
				flagImageTagLatest            bool
				flagLivenessProbe             bool
				flagReadnessProbe             bool
				flagPrivilegedAllowed         bool
				flagNotReadOnlyRootFilesystem bool
				flagNotRunAsNonRoot           bool
			)
			if item.Spec.Template.Spec.SecurityContext != nil && item.Spec.Template.Spec.SecurityContext.RunAsNonRoot != nil && *item.Spec.Template.Spec.SecurityContext.RunAsNonRoot {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Daemonsets,
					Message:   "NotRunAsNonRoot",
					Level:     "danger",
				})
				flagNotRunAsNonRoot = true
			}
			for _, container := range item.Spec.Template.Spec.Containers {
				if !flagCpuLimit && (container.Resources.Limits.Cpu() == nil || container.Resources.Limits.Cpu().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "NoCPULimits",
						Level:     "danger",
					})
					flagCpuLimit = true
				}

				if !flagCpuRequest && (container.Resources.Requests.Cpu() == nil || container.Resources.Requests.Cpu().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "NoCPURequests",
						Level:     "danger",
					})
					flagCpuRequest = true
				}

				if !flagMemLimit && (container.Resources.Limits.Memory() == nil || container.Resources.Limits.Memory().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "NoMemoryLimits",
						Level:     "danger",
					})
					flagMemLimit = true
				}

				if !flagMemRequest && (container.Resources.Requests.Memory() == nil || container.Resources.Requests.Memory().MilliValue() == 0) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "NoMemoryRequest",
						Level:     "danger",
					})
					flagMemRequest = true
				}

				// if container.SecurityContext != nil && reflect.DeepEqual(container.SecurityContext.Capabilities.Add, []corev1.Capability{"NET_ADMIN", "SYS_ADMIN", "ALL"}) {
				// 	validateResult = append(validateResult, ValidateResult{
				// 		Name:      item.Name,
				// 		Namespace: item.Namespace,
				// 		Type:      conf.Daemonsets,
				// 		Message:   "HighRiskCapabilities",
				// 		Level:     "danger",
				// 	})
				// }
				for _, portItem := range container.Ports {
					if !flagHostPort && portItem.HostPort > 0 {
						validateResult = append(validateResult, ValidateResult{
							Name:      item.Name,
							Namespace: item.Namespace,
							Type:      conf.Daemonsets,
							Message:   "HostPortAllowed",
							Level:     "danger",
						})
						flagHostPort = true
					}
				}

				if !flagImagePull && container.ImagePullPolicy != "Always" {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "ImagePullPolicyNotAlways",
						Level:     "warning",
					})
					flagImagePull = true
				}
				flag, _ := regexp.Match("^.+:.+$", []byte(container.Image))
				if !flag && !flagImageTagMiss {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "ImageTagMiss",
						Level:     "danger",
					})
					flagImageTagMiss = true
				}

				flag, _ = regexp.Match("^.+:latest$", []byte(container.Image))

				if flag && !flagImageTagLatest {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "ImageTagIsLatest",
						Level:     "danger",
					})
					flagImageTagLatest = true
				}

				// if container.SecurityContext != nil && reflect.DeepEqual(container.SecurityContext.Capabilities.Add, []corev1.Capability{"CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID", "SETFCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"}) {
				// 	validateResult = append(validateResult, ValidateResult{
				// 		Name:      item.Name,
				// 		Namespace: item.Namespace,
				// 		Type:      conf.Daemonsets,
				// 		Message:   "InsecureCapabilities",
				// 		Level:     "danger",
				// 	})
				// }
				if !flagLivenessProbe && container.LivenessProbe == nil {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "NoLivenessProbe",
						Level:     "warning",
					})
					flagLivenessProbe = true
				}
				if !flagReadnessProbe && container.ReadinessProbe == nil {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "NoReadinessProbe",
						Level:     "warning",
					})
					flagReadnessProbe = true
				}
				if !flagPrivilegedAllowed && (container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "PrivilegedAllowed",
						Level:     "danger",
					})
					flagPrivilegedAllowed = true
				}
				if !flagNotReadOnlyRootFilesystem && (container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "NotReadOnlyRootFilesystem",
						Level:     "danger",
					})
					flagNotReadOnlyRootFilesystem = true
				}

				if !flagNotRunAsNonRoot && (container.SecurityContext != nil && container.SecurityContext.RunAsNonRoot != nil && *container.SecurityContext.RunAsNonRoot) {
					validateResult = append(validateResult, ValidateResult{
						Name:      item.Name,
						Namespace: item.Namespace,
						Type:      conf.Daemonsets,
						Message:   "NotRunAsNonRoot",
						Level:     "danger",
					})
					flagNotRunAsNonRoot = true
				}
			}
		}
	case conf.Events:
		resource, err := k.ClientSet.CoreV1().Events("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, item := range resource.Items {
			if item.Type != "Normal" {
				validateResult = append(validateResult, ValidateResult{
					Name:      item.Name,
					Namespace: item.Namespace,
					Type:      conf.Events,
					Message:   item.Reason,
					Level:     "danger",
					Reason:    item.Message,
				})
			}
		}
	case conf.Nodes:
		resource, err := k.ClientSet.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, item := range resource.Items {
			for _, condition := range item.Status.Conditions {
				if condition.Status == "False" {
					if strings.Contains(condition.Message, "has") && !strings.Contains(condition.Message, "has no") {
						validateResult = append(validateResult, ValidateResult{
							Name:      item.Name,
							Namespace: item.Namespace,
							Type:      conf.Nodes,
							Message:   condition.Reason,
							Level:     "warning",
							Reason:    condition.Message,
						})
					}
					if strings.Contains(condition.Message, "Has") && !strings.Contains(condition.Message, "HasNo") {
						validateResult = append(validateResult, ValidateResult{
							Name:      item.Name,
							Namespace: item.Namespace,
							Type:      conf.Nodes,
							Message:   condition.Reason,
							Level:     "warning",
							Reason:    condition.Message,
						})
					}
					if strings.Contains(condition.Message, "has no") && strings.Contains(condition.Reason, "HasNo") {
						validateResult = append(validateResult, ValidateResult{
							Name:      item.Name,
							Namespace: item.Namespace,
							Type:      conf.Nodes,
							Message:   condition.Reason,
							Level:     "warning",
							Reason:    condition.Message,
						})
					}
				}

			}

		}
	}
	return validateResult, nil
}
