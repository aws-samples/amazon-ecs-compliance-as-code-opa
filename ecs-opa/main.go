package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"log"
	"os"
	"strings"
)

var ctx context.Context
var module string
var store storage.Store
var compiler *ast.Compiler

func handler(event events.CloudWatchEvent) {

	var eventBridgeECSTaskStatusChangeEventDetail EventBridgeECSTaskStatusChangeEventDetail
	err := json.Unmarshal(event.Detail, &eventBridgeECSTaskStatusChangeEventDetail)
	if err != nil {
		log.Fatal("error during event unmarshaling:", err)
	}

	clusterArn := eventBridgeECSTaskStatusChangeEventDetail.ClusterArn
	taskArn := eventBridgeECSTaskStatusChangeEventDetail.TaskArn
	taskDefinitionArn := eventBridgeECSTaskStatusChangeEventDetail.TaskDefinitionArn

	var accountId = getAccountId()

	rs, err := evaluateRules(event.Detail, accountId)
	if err != nil {
		log.Fatal("evaluateRules failed", err)
	}

	var t interface{}
	var compliedWithPolicy bool

	t = rs[0].Expressions[0].Value

	switch t := t.(type) {
	default:
		log.Fatal("unexpected type %T\n", t)
	case bool:
		compliedWithPolicy = bool(t)
	}

	if !compliedWithPolicy { // Take corrective action

		if listServicesOutput, listServicesError := listServices(clusterArn); listServicesError != nil {
			listServicesErrorHandler(listServicesError)
		} else {
			var serviceArns []string
			serviceArns = aws.StringValueSlice(listServicesOutput.ServiceArns)
			if len(serviceArns) > 1 {
				log.Fatal("cannot process more than one service per cluster (cluster ARN: %s)", clusterArn)
			} else if len(serviceArns) == 1 {
				serviceName := parseServiceName(serviceArns[0])

				stopTask(clusterArn, taskArn)
				setServiceDesiredCountToZero(clusterArn, serviceName)
				deregisterTaskDefinition(taskDefinitionArn)
				sendNotificationEvent(clusterArn, serviceArns[0], taskDefinitionArn, taskArn)
			}
		}
	}

}

func main() {
	lambda.Start(handler)
}

func evaluateRules(input interface{}, accountId string) (rego.ResultSet, error) {

	ctx := context.Background()

	var region = os.Getenv("AWS_REGION")

	module = `
		package ecstaskstatuswatcher
		
		default allow = false
		
		allow =true {
		    not any_non_approved_container_registry
		}
		
		any_non_approved_container_registry {
		    some i
		    input.containers[i]
		    not startswith(input.containers[i].image, "` + accountId + `.dkr.ecr.` + region + `.amazonaws.com") 
		}
	`

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err := ast.CompileModules(map[string]string{
		"ecstaskstatuswatcher.rego": module,
	})

	if err != nil {
		log.Fatal("module compilation failed due to:", err)
	}

	rego := rego.New(
		rego.Query("data.ecstaskstatuswatcher.allow"),
		rego.Compiler(compiler),
		rego.Input(input),
	)

	// Run evaluation.
	return rego.Eval(ctx)
}

func listServices(clusterArn string) (*ecs.ListServicesOutput, error) {
	// Create client
	mySession := session.Must(session.NewSession())
	var svc = ecs.New(mySession)

	listServicesInput := ecs.ListServicesInput{Cluster: aws.String(clusterArn)}
	return svc.ListServices(&listServicesInput)
}

func setServiceDesiredCountToZero(clusterArn string, serviceName string) {
	fmt.Printf("Service %s to be updated with desired capacity set to 0\n", serviceName)

	// Set the desired count to 0
	updateServiceInput := ecs.UpdateServiceInput{Cluster: aws.String(clusterArn),
		Service:      aws.String(serviceName),
		DesiredCount: aws.Int64(0)}

	mySession := session.Must(session.NewSession())
	var svc = ecs.New(mySession)

	_, err := svc.UpdateService(&updateServiceInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ecs.ErrCodeServerException:
				fmt.Println(ecs.ErrCodeServerException, aerr.Error())
			case ecs.ErrCodeClientException:
				fmt.Println(ecs.ErrCodeClientException, aerr.Error())
			case ecs.ErrCodeInvalidParameterException:
				fmt.Println(ecs.ErrCodeInvalidParameterException, aerr.Error())
			case ecs.ErrCodeClusterNotFoundException:
				fmt.Println(ecs.ErrCodeClusterNotFoundException, aerr.Error())
			case ecs.ErrCodeServiceNotFoundException:
				fmt.Println(ecs.ErrCodeServiceNotFoundException, aerr.Error())
			case ecs.ErrCodeServiceNotActiveException:
				fmt.Println(ecs.ErrCodeServiceNotActiveException, aerr.Error())
			case ecs.ErrCodePlatformUnknownException:
				fmt.Println(ecs.ErrCodePlatformUnknownException, aerr.Error())
			case ecs.ErrCodePlatformTaskDefinitionIncompatibilityException:
				fmt.Println(ecs.ErrCodePlatformTaskDefinitionIncompatibilityException, aerr.Error())
			case ecs.ErrCodeAccessDeniedException:
				fmt.Println(ecs.ErrCodeAccessDeniedException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}

		return

	}
}

func stopTask(clusterArn string, taskArn string) {
	// Stop the task
	stopTaskInput := ecs.StopTaskInput{Cluster: aws.String(clusterArn),
		Reason: aws.String("lambda stopping ecs task"), Task: aws.String(taskArn)}

	// Create client
	mySession := session.Must(session.NewSession())
	var svc = ecs.New(mySession)

	_, err := svc.StopTask(&stopTaskInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ecs.ErrCodeServerException:
				fmt.Println(ecs.ErrCodeServerException, aerr.Error())
			case ecs.ErrCodeClientException:
				fmt.Println(ecs.ErrCodeClientException, aerr.Error())
			case ecs.ErrCodeInvalidParameterException:
				fmt.Println(ecs.ErrCodeInvalidParameterException, aerr.Error())
			case ecs.ErrCodeClusterNotFoundException:
				fmt.Println(ecs.ErrCodeClusterNotFoundException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}
}

func deregisterTaskDefinition(taskDefinitionArn string) {
	deregisterTaskDefinitionInput := ecs.DeregisterTaskDefinitionInput{TaskDefinition: aws.String(taskDefinitionArn)}

	// Create client
	mySession := session.Must(session.NewSession())
	var svc = ecs.New(mySession)

	_, err := svc.DeregisterTaskDefinition(&deregisterTaskDefinitionInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ecs.ErrCodeServerException:
				fmt.Println(ecs.ErrCodeServerException, aerr.Error())
			case ecs.ErrCodeClientException:
				fmt.Println(ecs.ErrCodeClientException, aerr.Error())
			case ecs.ErrCodeInvalidParameterException:
				fmt.Println(ecs.ErrCodeInvalidParameterException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

}

func sendNotificationEvent(clusterArn, serviceArn, taskDefinitionArn, taskArn string) {
	if message, err := marshalNotificationMessage(clusterArn, serviceArn, taskDefinitionArn, taskArn); err == nil {
		publishInput := sns.PublishInput{Message: aws.String(string(message)),
			TopicArn: aws.String(os.Getenv("SNS_TOPIC_ARN"))}
		// Create client
		mySession := session.Must(session.NewSession())
		var svc = sns.New(mySession)

		if _, err := svc.Publish(&publishInput); err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				fmt.Println(aerr.Error())
			} else {
				fmt.Println(err.Error())
			}
			return
		}
	}
}

func marshalNotificationMessage(clusterArn, serviceArn, taskDefinitionArn, taskArn string) ([]byte, error) {
	m := NotificationMessage{clusterArn, serviceArn, taskDefinitionArn, taskArn}

	return json.Marshal(m)
}

func getAccountId() string {
	svc := sts.New(session.New())
	input := &sts.GetCallerIdentityInput{}

	result, err := svc.GetCallerIdentity(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
				fmt.Println(aerr.Error())
		} else {
			fmt.Println(err.Error())
		}
		log.Fatal("Error getting account id")
	}

	return aws.StringValue(result.Account)
}

func parseServiceName(serviceName string) string {
	return strings.Split(serviceName, "/")[2]
}

func listServicesErrorHandler(listServicesError error) {

	if listServicesError != nil {
		if aerr, ok := listServicesError.(awserr.Error); ok {
			switch aerr.Code() {
			case ecs.ErrCodeServerException:
				fmt.Println(ecs.ErrCodeServerException, aerr.Error())
			case ecs.ErrCodeClientException:
				fmt.Println(ecs.ErrCodeClientException, aerr.Error())
			case ecs.ErrCodeInvalidParameterException:
				fmt.Println(ecs.ErrCodeInvalidParameterException, aerr.Error())
			case ecs.ErrCodeClusterNotFoundException:
				fmt.Println(ecs.ErrCodeClusterNotFoundException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(listServicesError.Error())
		}
		return
	}
}

type EventBridgeECSTaskStatusChangeEventDetail struct {
	ClusterArn        string `json:"clusterArn"`
	TaskArn           string `json:"taskArn"`
	TaskDefinitionArn string `json:"taskDefinitionArn"`
}

type NotificationMessage struct {
	ClusterArn        string
	ServiceArn        string
	TaskDefinitionArn string
	TaskArn           string
}