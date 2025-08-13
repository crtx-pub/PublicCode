#!/bin/bash
#
# check_all_cloud_perms.sh - v3.0 (Definitive)
#
# This script checks if the current cloud identity has the necessary permissions
# required for various Palo Alto Networks products across AWS, Azure, and GCP.
#
# v3.0 Enhancements:
# - Replaced specific cloudcontrol/cloudformation checks with 'cloudformation:*'.
# - Confirmed deduplication logic for the final policy generator.
#
# v2.9 Enhancements:
# - Corrected the service prefix for AWS Cloud Control API to 'cloudcontrolapi'.
#
# v2.7 Enhancements:
# - Added an interactive prompt to save the generated AWS IAM policy to a file.
# - Corrected invalid IAM service prefixes (e.g., bedrock-agent -> bedrock).
#
# Usage:
#   1. Ensure cloud CLIs (aws/az/gcloud) and 'jq' are installed.
#   2. Log in to the desired cloud provider.
#   3. Run the script: ./check_all_cloud_perms.sh
#

# --- Global Setup and Pre-checks ---
set -o pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counter and array for missing permissions
MISSING_ITEMS_COUNT=0
AWS_MISSING_PERMS=()

# Temporary files
AZURE_EFFECTIVE_PERMS_FILE=$(mktemp)
GCP_IAM_POLICY_FILE=$(mktemp)

# Cleanup trap to remove temp files on exit
trap 'rm -f "$AZURE_EFFECTIVE_PERMS_FILE" "$GCP_IAM_POLICY_FILE"' EXIT

################################################################################
#
# AWS PERMISSION DEFINITIONS AND FUNCTIONS
#
################################################################################

AWS_EC2_PERMS=( "ec2:ModifySnapshotAttribute" "ec2:DeleteSnapshot" "ec2:CreateTags" "ec2:DescribeSnapshots" "ec2:CreateSnapshot" "ec2:CopySnapshot" "kms:DescribeKey" "kms:GenerateDataKeyWithoutPlaintext" "kms:CreateGrant" )
AWS_DSPM_PERMS=( "s3:ListAllMyBuckets" "rds:DeleteDBSnapshot" "rds:AddTagsToResource" "rds:CancelExportTask" "rds:CreateDBClusterSnapshot" "rds:CreateDBSnapshot" "rds:DescribeDBInstances" "rds:ListTagsForResource" "rds:StartExportTask" "s3:PutObject" "s3:DeleteObject" "s3:GetObject" "kms:DescribeKey" "kms:GenerateDataKeyWithoutPlaintext" "kms:CreateGrant" "iam:PassRole" "dynamodb:DescribeTable" "dynamodb:Scan" "cloudwatch:GetMetricStatistics" "memorydb:DescribeClusters" )
# [UPDATED v3.0] Replaced specific actions with cloudformation:*
AWS_DISCOVERY_PERMS=(
    "ds:DescribeDirectories" "ds:ListTagsForResource" "directconnect:DescribeConnections"
    "directconnect:DescribeDirectConnectGateways" "directconnect:DescribeVirtualInterfaces"
    "glue:GetSecurityConfigurations" "workspaces:DescribeTags" "workspaces:DescribeWorkspaceDirectories"
    "workspaces:DescribeWorkspaces" "apigateway:GET" "cloudformation:GetResource"
    "bedrock:GetAgent" "bedrock:GetDataSource" "bedrock:GetKnowledgeBase" "bedrock:ListAgentAliases"
    "bedrock:ListAgentKnowledgeBases" "bedrock:ListAgents" "bedrock:ListDataSources"
    "bedrock:ListCustomModels" "cloudformation:*" "cloudwatch:DescribeAlarms"
    "comprehendmedical:ListEntitiesDetectionV2Jobs" "config:DescribeDeliveryChannels"
    "elasticfilesystem:DescribeFileSystemPolicy" "elasticloadbalancing:DescribeSSLPolicies"
    "forecast:ListTagsForResource" "glue:GetConnections" "glue:GetResourcePolicies"
    "iam:ListRoles" "aoss:ListCollections" "s3:GetAccessPointPolicy" "s3:GetAccessPointPolicyStatus"
    "s3:GetAccountPublicAccessBlock" "s3:ListAccessPoints" "servicecatalog:ListApplications"
    "servicecatalog:ListAttributeGroups" "sqs:ListQueues" "iam:GetAccountPasswordPolicy"
    "iam:ListAccountAliases"
)
AWS_REGISTRY_SCAN_PERMS=( "ecr:BatchGetImage" "ecr:GetDownloadUrlForLayer" "ecr:GetAuthorizationToken" "ecr-public:GetAuthorizationToken" )
AWS_LOG_COLLECTION_PERMS=( "s3:GetObject" "s3:ListBucket" "sqs:ReceiveMessage" "sqs:DeleteMessage" "sqs:GetQueueAttributes" )

check_aws_permission() {
    local permission=$1
    local output
    local exit_code
    local timeout_params="--cli-connect-timeout 15 --cli-read-timeout 15"
    echo -n "  Checking action: ${permission}... "

    output=$(aws iam simulate-principal-policy $timeout_params --policy-source-arn "$CALLER_ARN" --action-names "$permission" --output json 2>&1)
    exit_code=$?

    if [[ $exit_code -ne 0 ]] && echo "$output" | grep -q "iam:SimulatePrincipalPolicy"; then
        echo -e "${RED}ACTION REQUIRED${NC}"
        echo -e "    ${RED}└─ Your user is missing the core permission needed to perform checks." >&2
        echo -e "    ${YELLOW}To fix this, attach the following IAM policy to the user '${PRINCIPAL_NAME}':${NC}" >&2
        printf >&2 '%s\n' \
'    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:SimulatePrincipalPolicy",
                "Resource": "*"
            }
        ]
    }'
        echo -e "\n${RED}Script cannot continue without this core permission. Please add the policy and re-run.${NC}" >&2
        exit 1
    elif [[ $exit_code -ne 0 ]]; then
        echo -e "${YELLOW}COULD NOT VERIFY${NC}"
        echo -e "    ${YELLOW}└─ Command failed. Check network or see error below:${NC}"
        echo -e "    ${RED}$(echo "$output" | head -n 1)${NC}"
        ((MISSING_ITEMS_COUNT++))
    else
        local decision
        decision=$(echo "$output" | jq -r '.EvaluationResults[0].EvalDecision')

        if [[ "$decision" == "allowed" ]]; then
            echo -e "${GREEN}Allowed${NC}"
        else
            local org_decision_raw
            org_decision_raw=$(echo "$output" | jq '.EvaluationResults[0].OrganizationsDecisionDetail')
            local hint=""
            if [[ "$org_decision_raw" != "null" ]] && [[ $(echo "$org_decision_raw" | jq -r '.AllowByOrganizations') == "false" ]]; then
                 hint=" (Hint: A Service Control Policy (SCP) may be the cause)"
            fi
            echo -e "${RED}DENIED${NC} (Reason: ${decision})${YELLOW}${hint}${NC}"
            echo -e "    ${RED}└─ Missing permission: ${permission}${NC}"
            ((MISSING_ITEMS_COUNT++))
            AWS_MISSING_PERMS+=("$permission")
        fi
    fi
}

main_aws() {
    echo "Checking for AWS dependencies (aws, jq)..."; if ! command -v aws &>/dev/null||! command -v jq &>/dev/null; then echo -e "${RED}Error: AWS CLI and/or jq not found.${NC}"; exit 1; fi; echo -e "${GREEN}Deps OK.${NC}\n"
    echo "Verifying AWS credentials..."
    if ! CALLER_ARN=$(aws sts get-caller-identity --query Arn 2>/dev/null | tr -d '"'); then echo -e "${RED}AWS login failed or timed out. Check network and credentials, then re-run.${NC}"; exit 1; fi
    if [[ -z "$CALLER_ARN" ]]; then echo -e "${RED}Could not determine AWS Principal. Check credentials.${NC}"; exit 1; fi
    
    if [[ $CALLER_ARN == *:user/* ]]; then
        PRINCIPAL_NAME=$(echo "$CALLER_ARN" | cut -d'/' -f2)
    else
        PRINCIPAL_NAME=$(echo "$CALLER_ARN")
    fi
    
    echo -e "Principal: ${GREEN}${CALLER_ARN}${NC}\n"
    echo -e "${YELLOW}NOTE:${NC} This script does not simulate conditional contexts like resource tags.\n"
    echo -e "${CYAN}--- Checking EC2 Permissions ---${NC}"; for p in "${AWS_EC2_PERMS[@]}"; do check_aws_permission "$p"; done; echo
    echo -e "${CYAN}--- Checking DSPM Permissions ---${NC}"; for p in "${AWS_DSPM_PERMS[@]}"; do check_aws_permission "$p"; done; echo
    echo -e "${CYAN}--- Checking Discovery Engine Permissions ---${NC}"; for p in "${AWS_DISCOVERY_PERMS[@]}"; do check_aws_permission "$p"; done; echo
    echo -e "${CYAN}--- Checking Registry Scan Permissions ---${NC}"; for p in "${AWS_REGISTRY_SCAN_PERMS[@]}"; do check_aws_permission "$p"; done; echo
    echo -e "${CYAN}--- Checking Log Collection Permissions ---${NC}"; for p in "${AWS_LOG_COLLECTION_PERMS[@]}"; do check_aws_permission "$p"; done; echo
}

################################################################################
#
# AZURE PERMISSION DEFINITIONS AND FUNCTIONS
#
################################################################################

AZURE_ADS_PERMS=("Microsoft.Compute/snapshots/write" "Microsoft.Compute/snapshots/delete" "Microsoft.Compute/virtualMachines/read" "Microsoft.Compute/snapshots/read")
AZURE_DSPM_PERMS=( "Microsoft.Storage/storageAccounts/PrivateEndpointConnectionsApproval/action" "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read" "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read" "Microsoft.Storage/storageAccounts/listKeys/action" "Microsoft.Storage/storageAccounts/ListAccountSas/action" "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action" "Microsoft.DocumentDB/databaseAccounts/listKeys/" "Microsoft.Storage/storageAccounts/tableServices/tables/entities/read" "Microsoft.CognitiveServices/*/read" "Microsoft.CognitiveServices/*/action" "*/read" "Microsoft.Network/routeTables/write" "Microsoft.Network/routeTables/join/action" "Microsoft.Network/routeTables/delete" "Microsoft.Network/virtualNetworks/delete" "Microsoft.Network/virtualNetworks/join/action" "Microsoft.Network/virtualNetworks/subnets/delete" "Microsoft.Network/virtualNetworks/subnets/join/action" "Microsoft.Network/virtualNetworks/subnets/write" "Microsoft.Network/virtualNetworks/write" "Microsoft.Network/networkSecurityGroups/securityRules/write" "Microsoft.Network/networkSecurityGroups/securityRules/delete" "Microsoft.Network/networkSecurityGroups/join/action" "Microsoft.Network/networkSecurityGroups/delete" "Microsoft.Network/networkSecurityGroups/write" "Microsoft.Sql/servers/databases/read" "Microsoft.Sql/servers/databases/write" "Microsoft.Sql/servers/databases/resume/action" "Microsoft.Sql/servers/databases/delete" "Microsoft.Sql/servers/delete" "Microsoft.Sql/servers/write" "Microsoft.Sql/servers/virtualNetworkRules/write" "Microsoft.Sql/servers/privateEndpointConnectionsApproval/action" "Microsoft.Sql/managedInstances/write" "Microsoft.Sql/managedInstances/databases/write" "Microsoft.Sql/managedInstances/delete" )
AZURE_DISCOVERY_PERMS=($(echo "Microsoft.ContainerInstance/containerGroups/containers/exec/action Microsoft.ContainerRegistry/registries/webhooks/getCallbackConfig/action Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action Microsoft.DocumentDB/databaseAccounts/listKeys/action Microsoft.DocumentDB/databaseAccounts/readonlykeys/action Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action Microsoft.Network/networkInterfaces/effectiveRouteTable/action Microsoft.Network/networkWatchers/queryFlowLogStatus/* Microsoft.Network/networkWatchers/read Microsoft.Network/networkWatchers/securityGroupView/action Microsoft.Network/virtualwans/vpnconfiguration/action Microsoft.Storage/storageAccounts/listKeys/action Microsoft.Web/sites/config/list/action Microsoft.Resources/subscriptions/resourceGroups/write $(for p in {Advisor,AlertsManagement,AnalysisServices,ApiManagement,AppConfiguration,AppPlatform,Attestation,Authorization,Automanage,Automation,AzureStackHCI,Batch,Blueprint,BotService,Cache,Cdn,Chaos,ClassicCompute,ClassicNetwork,ClassicStorage,CognitiveServices,Communication,Compute,Confluent,ContainerInstance,ContainerRegistry,ContainerService,DBforMariaDB,DBforMySQL,DBforPostgreSQL,Dashboard,DataBoxEdge,DataFactory,DataLakeAnalytics,DataLakeStore,DataMigration,DataShare,Databricks,Datadog,DesktopVirtualization,DevCenter,DevTestLab,Devices,DigitalTwins,DocumentDB,DomainRegistration,Easm,Elastic,EventGrid,EventHub,HDInsight,HealthBot,HealthcareApis,HybridCompute,Insights,IoTCentral,KeyVault,Kusto,LabServices,LoadTestService,Logic,MachineLearningServices,ManagedIdentity,ManagedServices,Management,Maps,Migrate,MixedReality,NetApp,Network,NetworkFunction,NotificationHubs,OperationalInsights,Orbital,PowerBIDedicated,Quantum,RecoveryServices,RedHatOpenShift,Relay,Resources,SaaS,Search,Security,ServiceBus,ServiceFabric,SignalRService,Solutions,Sql,SqlVirtualMachine,Storage,StorageCache,StorageMover,StorageSync,StreamAnalytics,Subscription,Synapse,VideoIndexer,VisualStudio,Web,Workloads,classicCompute,app,monitor,network}; do echo Microsoft.$p/*/{read,action}; done)" | tr ' ' '\n' | sort -u))
AZURE_DISCOVERY_GRAPH_PERMS=( "Domain.Read.All" "EntitlementManagement.Read.All" "User.Read.All" "Policy.ReadWrite.AuthenticationMethod" "GroupMember.Read.All" "RoleManagement.Read.All" "Group.Read.All" "AuditLog.Read.All" "Policy.Read.All" "IdentityProvider.Read.All" "Directory.Read.All" "Organization.Read.All" )
AZURE_LOG_COLLECTION_ROLES=("Azure Event Hubs Data Receiver" "Storage Blob Data Contributor")
AZURE_REGISTRY_SCAN_PERMS=( "Microsoft.ContainerRegistry/registries/metadata/read" "Microsoft.ContainerRegistry/registries/pull/read" "Microsoft.ContainerRegistry/registries/read" "Microsoft.ContainerRegistry/registries/webhooks/getCallbackConfig/action" )

check_azure_permission() { local p=$1 f=0; echo -n "  Checking action: ${p}... "; if grep -qixf <(echo "$p"|sed -e 's|/*$|/*|' -e 's|/$|/*|' -e 's|/*$|/*|' -e 's|/*$|/read|' -e 's|/*$|/action|'|sed 's|//*|/|g'; echo "$p"; echo "${p%/*}/*"; echo "${p%/*/*}/*"; echo "*") "$AZURE_EFFECTIVE_PERMS_FILE"; then f=1; fi; if [[ $f -eq 1 ]]; then echo -e "${GREEN}Allowed${NC}"; else echo -e "${RED}DENIED${NC}"; echo -e "    ${RED}└─ Missing: ${p}${NC}"; ((MISSING_ITEMS_COUNT++)); fi; }
check_azure_role() { local r=$1; echo -n "  Checking role: \"${r}\"... "; res=$(az role assignment list --assignee "$ASSIGNEE_ID" --role "$r" --scope "/subscriptions/$SUBSCRIPTION_ID" --query "[0].id" -o tsv 2>/dev/null); if [[ -n "$res" ]]; then echo -e "${GREEN}Assigned${NC}"; else echo -e "${RED}NOT ASSIGNED${NC}"; echo -e "    ${RED}└─ Missing: ${r}${NC}"; ((MISSING_ITEMS_COUNT++)); fi; }

main_azure() {
    echo "Checking for Azure dependencies (az, jq)..."; if ! command -v az &>/dev/null||! command -v jq &>/dev/null; then echo -e "${RED}Error: Azure CLI and/or jq not found.${NC}"; exit 1; fi; echo -e "${GREEN}Deps OK.${NC}\n"
    echo "Verifying Azure login..."; if ! az account show >/dev/null 2>&1; then echo -e "${RED}Azure login failed. Run 'az login'.${NC}"; exit 1; fi
    subs=$(az account list --query "[?state=='Enabled'].{name:name, id:id}" -o json); if [ "$(echo "$subs"|jq 'length')" -gt 1 ]; then echo "Select Azure subscription:"; PS3="Enter num: "; select sn in $(echo "$subs"|jq -r '.[].name'); do if [ -n "$sn" ]; then SUBSCRIPTION_ID=$(echo "$subs"|jq -r ".[]|select(.name==\"$sn\")|.id"); az account set -s "$SUBSCRIPTION_ID"; break; else echo "Invalid."; fi; done; fi
    SUBSCRIPTION_ID=$(az account show --query id -o tsv); SUB_NAME=$(az account show --query name -o tsv); ASSIGNEE_ID=$(az ad signed-in-user show --query id -o tsv); echo -e "\nSubscription: ${GREEN}${SUB_NAME}${NC}\n"
    echo "Fetching effective permissions..."; if ! az rest --method get --url "/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"|jq -r '.value[].actions[]' > "$AZURE_EFFECTIVE_PERMS_FILE"; then echo -e "${RED}Perm fetch failed. Check 'Microsoft.Authorization/permissions/read'.${NC}"; exit 1; fi; echo -e "${GREEN}OK.${NC}\n"
    echo -e "${CYAN}--- Checking Azure ADS Permissions ---${NC}"; for p in "${AZURE_ADS_PERMS[@]}"; do check_azure_permission "$p"; done; echo
    echo -e "${CYAN}--- Checking Azure DSPM Permissions ---${NC}"; for p in "${AZURE_DSPM_PERMS[@]}"; do check_azure_permission "$p"; done; echo
    echo -e "${CYAN}--- Checking Azure Discovery Engine Permissions ---${NC}"; for p in "${AZURE_DISCOVERY_PERMS[@]}"; do check_azure_permission "$p"; done; echo
    echo -e "${CYAN}--- Checking Azure Registry Scan Permissions ---${NC}"; for p in "${AZURE_REGISTRY_SCAN_PERMS[@]}"; do check_azure_permission "$p"; done; echo
    echo -e "${CYAN}--- Checking Azure Log Collection Role Assignments ---${NC}"; for p in "${AZURE_LOG_COLLECTION_ROLES[@]}"; do check_azure_role "$p"; done; echo
    echo -e "${CYAN}--- MS Graph Permissions (Manual Check Required) ---${NC}"; echo -e "${YELLOW}The following apply to App Registrations, not users, and must be checked manually:${NC}"; for p in "${AZURE_DISCOVERY_GRAPH_PERMS[@]}"; do echo "  - ${p}"; done; echo
}

################################################################################
#
# GCP PERMISSION DEFINITIONS AND FUNCTIONS
#
################################################################################

GCP_COMPUTE_PERMS=( "compute.snapshots.get" "compute.snapshots.create" "compute.snapshots.delete" "compute.snapshots.setLabels" "compute.snapshots.useReadOnly" )
GCP_DSPM_PERMS=( "bigquery.bireservations.get" "bigquery.capacityCommitments.get" "bigquery.capacityCommitments.list" "bigquery.config.get" "bigquery.datasets.get" "bigquery.datasets.getIamPolicy" "bigquery.models.getData" "bigquery.models.getMetadata" "bigquery.models.list" "bigquery.routines.get" "bigquery.routines.list" "bigquery.tables.export" "bigquery.tables.get" "bigquery.tables.getData" "bigquery.tables.getIamPolicy" "bigquery.tables.list" "cloudsql.backupRuns.get" "cloudsql.backupRuns.create" "cloudsql.backupRuns.delete" "cloudsql.backupRuns.list" )
GCP_DSPM_ROLES=( "roles/cloudfunctions.viewer" "roles/container.clusterViewer" "roles/storage.objectViewer" "roles/firebaserules.viewer" )
GCP_DISCOVERY_PERMS=( "serviceusage.services.use" "storage.buckets.get" "storage.buckets.getIamPolicy" "storage.buckets.list" "storage.buckets.listEffectiveTags" "storage.buckets.listTagBindings" "storage.objects.getIamPolicy" "run.services.list" "run.jobs.list" "run.jobs.getIamPolicy" "cloudscheduler.jobs.list" "baremetalsolution.instances.list" "baremetalsolution.networks.list" "baremetalsolution.nfsshares.list" "baremetalsolution.volumes.list" "baremetalsolution.luns.list" "analyticshub.dataExchanges.list" "analyticshub.listings.getIamPolicy" "analyticshub.listings.list" "notebooks.locations.list" "notebooks.schedules.list" "composer.imageversions.list" "datamigration.connectionprofiles.list" "datamigration.connectionprofiles.getIamPolicy" "datamigration.conversionworkspaces.list" "datamigration.conversionworkspaces.getIamPolicy" "datamigration.migrationjobs.list" "datamigration.migrationjobs.getIamPolicy" "datamigration.privateconnections.list" "datamigration.privateconnections.getIamPolicy" "aiplatform.batchPredictionJobs.list" "aiplatform.nasJobs.list" "cloudsecurityscanner.scans.list" )
GCP_DISCOVERY_ROLES=( "roles/viewer" )
GCP_LOG_COLLECTION_ROLES=( "roles/pubsub.subscriber" )
GCP_REGISTRY_SCAN_PERMS=( "artifactregistry.repositories.downloadArtifacts" )
GCP_REGISTRY_SCAN_ROLES=( "roles/iam.serviceAccountTokenCreator" )

check_gcp_permissions_batch() {
    local perms_to_check_str=$1
    echo -n "  Checking a batch of permissions... "
    local granted_perms
    granted_perms=$(gcloud projects test-iam-permissions "$GCP_PROJECT_ID" --permissions="$perms_to_check_str" --format="value(permissions)" 2>/dev/null || true)

    if [[ -z "$granted_perms" ]] && ! gcloud projects describe "$GCP_PROJECT_ID" >/dev/null 2>&1; then
        echo -e "${RED}ERROR${NC}\n    ${RED}└─ Could not test permissions. Check connectivity or project access.${NC}"
        ((MISSING_ITEMS_COUNT++)); return
    fi

    IFS=',' read -r -a perms_array <<< "$perms_to_check_str"
    local all_found=true
    for p in "${perms_array[@]}"; do
        if ! echo "$granted_perms" | grep -q -w "$p"; then
            all_found=false
            echo -e "\n    ${RED}└─ Missing permission: ${p}${NC}"
            ((MISSING_ITEMS_COUNT++))
        fi
    done

    if [[ "$all_found" = true ]]; then echo -e "${GREEN}All Allowed${NC}"; else echo ""; fi
}

check_gcp_role() {
    local role_to_check=$1
    echo -n "  Checking role: ${role_to_check}... "
    if jq -e --arg ROLE "$role_to_check" --arg MEMBER "user:$GCP_USER_EMAIL" \
        '.bindings[] | select(.role == $ROLE) | .members[] | select(. == $MEMBER)' "$GCP_IAM_POLICY_FILE" >/dev/null; then
        echo -e "${GREEN}Assigned${NC}"
    else
        echo -e "${RED}NOT ASSIGNED${NC}"
        echo -e "    ${RED}└─ Missing role: ${role_to_check}${NC}"
        ((MISSING_ITEMS_COUNT++))
    fi
}

main_gcp() {
    echo "Checking for GCP dependencies (gcloud, jq)..."; if ! command -v gcloud &>/dev/null||! command -v jq &>/dev/null; then echo -e "${RED}Error: gcloud CLI and/or jq not found.${NC}"; exit 1; fi; echo -e "${GREEN}Deps OK.${NC}\n"
    echo "Verifying GCP login..."; if ! GCP_USER_EMAIL=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n 1); then echo -e "${RED}GCP login failed. Run 'gcloud auth login'.${NC}"; exit 1; fi
    if [[ -z "$GCP_USER_EMAIL" ]]; then echo -e "${RED}Could not determine active GCP account.${NC}"; exit 1; fi
    projects=$(gcloud projects list --format="value(projectId, name)"); if [ -n "$projects" ]; then echo "Select GCP project:"; PS3="Enter num: "; select proj_info in "${projects[@]}"; do if [ -n "$proj_info" ]; then GCP_PROJECT_ID=$(echo "$proj_info" | awk '{print $1}'); gcloud config set project "$GCP_PROJECT_ID"; break; else echo "Invalid."; fi; done; fi
    GCP_PROJECT_ID=$(gcloud config get-value project); echo -e "\nUser: ${GREEN}${GCP_USER_EMAIL}${NC}"; echo -e "Project: ${GREEN}${GCP_PROJECT_ID}${NC}\n"
    echo "Fetching project IAM policy for role checks..."; gcloud projects get-iam-policy "$GCP_PROJECT_ID" --format=json > "$GCP_IAM_POLICY_FILE"; echo -e "${GREEN}OK.${NC}\n"
    echo -e "${YELLOW}NOTE:${NC} This script does not validate conditional permissions or roles inherited from Google Groups.\n"

    echo -e "${CYAN}--- Checking GCP Compute Permissions ---${NC}"; check_gcp_permissions_batch "$(IFS=,; echo "${GCP_COMPUTE_PERMS[*]}")"; echo
    echo -e "${CYAN}--- Checking GCP DSPM Permissions & Roles ---${NC}"; check_gcp_permissions_batch "$(IFS=,; echo "${GCP_DSPM_PERMS[*]}")"; for r in "${GCP_DSPM_ROLES[@]}"; do check_gcp_role "$r"; done; echo
    echo -e "${CYAN}--- Checking GCP Discovery Engine Permissions & Roles ---${NC}"; check_gcp_permissions_batch "$(IFS=,; echo "${GCP_DISCOVERY_PERMS[*]}")"; for r in "${GCP_DISCOVERY_ROLES[@]}"; do check_gcp_role "$r"; done; echo
    echo -e "${CYAN}--- Checking GCP Log Collection Roles ---${NC}"; for r in "${GCP_LOG_COLLECTION_ROLES[@]}"; do check_gcp_role "$r"; done; echo
    echo -e "${CYAN}--- Checking GCP Registry Scan Permissions & Roles ---${NC}"; check_gcp_permissions_batch "$(IFS=,; echo "${GCP_REGISTRY_SCAN_PERMS[*]}")"; for r in "${GCP_REGISTRY_SCAN_ROLES[@]}"; do check_gcp_role "$r"; done; echo
}

generate_aws_policy() {
    if [[ "$CLOUD_PROVIDER" == "AWS" ]] && [ ${#AWS_MISSING_PERMS[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}--- Suggested IAM Policy (AWS) ---${NC}"
        
        local unique_missing_perms
        unique_missing_perms=($(printf "%s\n" "${AWS_MISSING_PERMS[@]}" | sort -u))
        local policy_json
        local actions_json_part=""
        
        local num_missing=${#unique_missing_perms[@]}
        for i in "${!unique_missing_perms[@]}"; do
            actions_json_part+="                \"${unique_missing_perms[$i]}\""
            if [[ $i -lt $(($num_missing - 1)) ]]; then
                actions_json_part+=","
            fi
            actions_json_part+=$'\n'
        done

        policy_json=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowMissingCortexCloudPermissions",
            "Effect": "Allow",
            "Action": [
${actions_json_part}            ],
            "Resource": "*"
        }
    ]
}
EOF
)
        echo "To fix the missing AWS permissions, you can create a new IAM policy with the following JSON:"
        echo "$policy_json"

        local export_choice
        read -p "Do you want to export this policy to a JSON file? (y/N) " export_choice
        if [[ "$export_choice" =~ ^[Yy]$ ]]; then
            local default_filename="AllowMissingCortexCloudPermissions.json"
            local user_filename
            read -p "Enter filename (default: ${default_filename}): " user_filename
            local filename=${user_filename:-$default_filename}
            echo "$policy_json" > "$filename"
            echo -e "${GREEN}Policy successfully saved to ${filename}${NC}"
        fi
    fi
}

################################################################################
#
# MAIN SCRIPT EXECUTION
#
################################################################################

clear
echo "=================================================="
echo " Palo Alto Networks - Cloud Permission Checker"
echo "=================================================="
echo

# Set CLOUD_PROVIDER if passed as an argument, otherwise prompt
CLOUD_PROVIDER=${1:-}
if [[ -z "$CLOUD_PROVIDER" ]]; then
    PS3="Select the cloud provider to check: "
    select provider in "AWS" "Azure" "GCP" "Quit"; do
        case $provider in
            AWS|Azure|GCP|Quit) CLOUD_PROVIDER=$provider; break;;
            *) echo "Invalid option $REPLY";;
        esac
    done
else
    case $CLOUD_PROVIDER in
        AWS|Azure|GCP) echo "Cloud provider '$CLOUD_PROVIDER' selected via command-line argument.";;
        *) echo "Invalid cloud provider '$CLOUD_PROVIDER'. Please use AWS, Azure, or GCP."; exit 1;;
    esac
fi

case $CLOUD_PROVIDER in
    AWS) main_aws;;
    Azure) main_azure;;
    GCP) main_gcp;;
    Quit) echo "Exiting."; exit 0;;
esac

# --- Final Summary ---
echo "----------------------------------------"
echo "            CHECK COMPLETE"
echo "----------------------------------------"
if [ "$MISSING_ITEMS_COUNT" -eq 0 ]; then
    echo -e "${GREEN}Success! All checkable permissions and roles are present.${NC}"
else
    echo -e "${RED}Found ${MISSING_ITEMS_COUNT} missing permission(s) or role(s).${NC}"
    echo -e "${YELLOW}Please review the items listed above and update your IAM configuration.${NC}"
    
    generate_aws_policy
fi
