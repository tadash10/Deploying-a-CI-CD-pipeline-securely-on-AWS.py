import subprocess
import json
import boto3
from botocore.exceptions import ClientError

# Replace these with your actual values
AWS_REGION = 'us-west-2'
PIPELINE_NAME = 'MyPipeline'
REPO_NAME = 'MyRepo'
BUCKET_NAME = 'my-pipeline-artifacts-bucket'
CODEBUILD_ROLE_NAME = 'CodeBuildServiceRole'
PIPELINE_ROLE_NAME = 'CodePipelineServiceRole'
SOURCE_STAGE_NAME = 'Source'
BUILD_STAGE_NAME = 'Build'
DEPLOY_STAGE_NAME = 'Deploy'
GITHUB_OAUTH_SECRET_NAME = 'github-oauth-token'

# Initialize AWS clients
iam_client = boto3.client('iam', region_name=AWS_REGION)
s3_client = boto3.client('s3', region_name=AWS_REGION)
secretsmanager_client = boto3.client('secretsmanager', region_name=AWS_REGION)
codebuild_client = boto3.client('codebuild', region_name=AWS_REGION)
codepipeline_client = boto3.client('codepipeline', region_name=AWS_REGION)
logs_client = boto3.client('logs', region_name=AWS_REGION)

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        result.check_returncode()
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e.stderr}")
        raise

def create_s3_bucket(bucket_name):
    try:
        # Create the S3 bucket
        command = f"aws s3api create-bucket --bucket {bucket_name} --region {AWS_REGION} --create-bucket-configuration LocationConstraint={AWS_REGION}"
        run_command(command)
        print(f"S3 bucket '{bucket_name}' created.")
        
        # Set bucket policy to restrict public access and allow necessary actions
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Condition": {
                        "Bool": {
                            "aws:PublicAccess": "true"
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:ListBucket"
                    ],
                    "Resource": [f"arn:aws:s3:::{bucket_name}/*"],
                    "Condition": {
                        "StringEquals": {
                            "aws:userid": "CodePipeline and CodeBuild"
                        }
                    }
                }
            ]
        }
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))
        print(f"S3 bucket policy updated for '{bucket_name}'.")

        # Enable server-side encryption
        encryption_config = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        }
        s3_client.put_bucket_encryption(Bucket=bucket_name, ServerSideEncryptionConfiguration=encryption_config)
        print(f"Server-side encryption enabled for S3 bucket '{bucket_name}'.")
    except ClientError as e:
        print(f"Error managing S3 bucket: {e}")
        raise

def create_iam_role(role_name, assume_role_policy_document, policy_document, role_description):
    try:
        # Create the IAM role
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=assume_role_policy_document,
            Description=role_description
        )
        role_arn = response['Role']['Arn']
        print(f"IAM Role '{role_name}' created with ARN {role_arn}.")

        # Attach the policy to the role
        policy_response = iam_client.create_policy(
            PolicyName=f'{role_name}Policy',
            PolicyDocument=json.dumps(policy_document)
        )
        policy_arn = policy_response['Policy']['Arn']
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        print(f"Policy '{policy_arn}' attached to role '{role_name}'.")

        return role_arn
    except ClientError as e:
        print(f"Error creating IAM role or attaching policy: {e}")
        raise

def get_secret(secret_name):
    try:
        response = secretsmanager_client.get_secret_value(SecretId=secret_name)
        return response['SecretString']
    except ClientError as e:
        print(f"Error retrieving secret: {e}")
        raise

def create_codebuild_project(project_name, role_arn, s3_bucket):
    try:
        command = f"""
        aws codebuild create-project \
            --name {project_name} \
            --source type=GITHUB,location=https://github.com/myorg/{REPO_NAME}.git \
            --artifacts type=S3,location={s3_bucket} \
            --environment type=LINUX_CONTAINER,computeType=BUILD_GENERAL1_SMALL,image=aws/codebuild/standard:5.0 \
            --service-role {role_arn} \
            --region {AWS_REGION}
        """
        run_command(command)
        print(f"CodeBuild project '{project_name}' created.")
    except ClientError as e:
        print(f"Error creating CodeBuild project: {e}")
        raise

def create_codepipeline():
    try:
        github_oauth_token = get_secret(GITHUB_OAUTH_SECRET_NAME)
        
        pipeline_json = {
            "pipeline": {
                "name": PIPELINE_NAME,
                "roleArn": f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:role/{PIPELINE_ROLE_NAME}",
                "artifactStore": {
                    "type": "S3",
                    "location": BUCKET_NAME
                },
                "stages": [
                    {
                        "name": SOURCE_STAGE_NAME,
                        "actions": [
                            {
                                "name": "SourceAction",
                                "actionTypeId": {
                                    "category": "Source",
                                    "owner": "ThirdParty",
                                    "provider": "GitHub",
                                    "version": "1"
                                },
                                "outputArtifacts": [{"name": "SourceArtifact"}],
                                "configuration": {
                                    "Owner": "myorg",
                                    "Repo": REPO_NAME,
                                    "Branch": "main",
                                    "OAuthToken": github_oauth_token
                                },
                                "runOrder": 1
                            }
                        ]
                    },
                    {
                        "name": BUILD_STAGE_NAME,
                        "actions": [
                            {
                                "name": "BuildAction",
                                "actionTypeId": {
                                    "category": "Build",
                                    "owner": "AWS",
                                    "provider": "CodeBuild",
                                    "version": "1"
                                },
                                "inputArtifacts": [{"name": "SourceArtifact"}],
                                "outputArtifacts": [{"name": "BuildArtifact"}],
                                "configuration": {
                                    "ProjectName": "MyCodeBuildProject"
                                },
                                "runOrder": 1
                            }
                        ]
                    }
                    # Add more stages as needed
                ]
            }
        }

        command = f"aws codepipeline create-pipeline --cli-input-json '{json.dumps(pipeline_json)}'"
        run_command(command)
        print(f"CodePipeline '{PIPELINE_NAME}' created.")
    except ClientError as e:
        print(f"Error creating CodePipeline: {e}")
        raise

def main():
    try:
        # Create S3 bucket and set policies
        create_s3_bucket(BUCKET_NAME)
        
        # Define IAM policies with least privilege
        codebuild_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "s3:GetObject",
                        "s3:PutObject"
                    ],
                    "Resource": "*"
                }
            ]
        }
        pipeline_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "codepipeline:StartPipelineExecution",
                        "codepipeline:GetPipelineExecution",
                        "codepipeline:GetPipelineState",
                        "codepipeline:PutJobSuccessResult",
                        "codepipeline:PutJobFailureResult"
                    ],
                    "Resource": "*"
                }
            ]
        }

        # Create IAM roles with custom policies
        codebuild_role_arn = create_iam_role(
            CODEBUILD_ROLE_NAME,
            json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "codebuild.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }),
            codebuild_policy_document,
            "Role for CodeBuild"
        )

        pipeline_role_arn = create_iam_role(
            PIPELINE_ROLE_NAME,
            json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "codepipeline.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }),
            pipeline_policy_document,
            "Role for CodePipeline"
        )

        # Create CodeBuild project
        create_codebuild_project("MyCodeBuildProject", codebuild_role_arn, BUCKET_NAME)
        
        # Create CodePipeline
        create_codepipeline()
        
    except Exception as e:
        print(f"Script failed with error: {e}")

if __name__ == '__main__':
    main()
