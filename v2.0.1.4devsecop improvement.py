import json
import boto3
from botocore.exceptions import ClientError
import logging
import os

# Configuration from environment variables
AWS_REGION = os.getenv('AWS_REGION', 'us-west-2')
PIPELINE_NAME = os.getenv('PIPELINE_NAME', 'MyPipeline')
REPO_NAME = os.getenv('REPO_NAME', 'MyRepo')
BUCKET_NAME = os.getenv('BUCKET_NAME', 'my-pipeline-artifacts-bucket')
CODEBUILD_ROLE_NAME = os.getenv('CODEBUILD_ROLE_NAME', 'CodeBuildServiceRole')
PIPELINE_ROLE_NAME = os.getenv('PIPELINE_ROLE_NAME', 'CodePipelineServiceRole')
SOURCE_STAGE_NAME = os.getenv('SOURCE_STAGE_NAME', 'Source')
BUILD_STAGE_NAME = os.getenv('BUILD_STAGE_NAME', 'Build')
DEPLOY_STAGE_NAME = os.getenv('DEPLOY_STAGE_NAME', 'Deploy')
GITHUB_OAUTH_SECRET_NAME = os.getenv('GITHUB_OAUTH_SECRET_NAME', 'github-oauth-token')

# Initialize AWS clients
iam_client = boto3.client('iam', region_name=AWS_REGION)
s3_client = boto3.client('s3', region_name=AWS_REGION)
secretsmanager_client = boto3.client('secretsmanager', region_name=AWS_REGION)
codebuild_client = boto3.client('codebuild', region_name=AWS_REGION)
codepipeline_client = boto3.client('codepipeline', region_name=AWS_REGION)
logs_client = boto3.client('logs', region_name=AWS_REGION)
sts_client = boto3.client('sts', region_name=AWS_REGION)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def run_command(command):
    import subprocess
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        result.check_returncode()
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running command: {e.stderr}")
        raise

def create_s3_bucket(bucket_name):
    try:
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': AWS_REGION}
        )
        logger.info(f"S3 bucket '{bucket_name}' created.")

        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        logger.info(f"Public access settings updated for S3 bucket '{bucket_name}'.")

        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        )
        logger.info(f"Server-side encryption enabled for S3 bucket '{bucket_name}'.")
    except ClientError as e:
        logger.error(f"Error managing S3 bucket: {e}")
        raise

def delete_s3_bucket(bucket_name):
    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        logger.info(f"S3 bucket '{bucket_name}' deleted.")
    except ClientError as e:
        logger.error(f"Error deleting S3 bucket: {e}")
        raise

def create_iam_role(role_name, assume_role_policy_document, policy_document, role_description):
    try:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=assume_role_policy_document,
            Description=role_description
        )
        role_arn = response['Role']['Arn']
        logger.info(f"IAM Role '{role_name}' created with ARN {role_arn}.")

        policy_response = iam_client.create_policy(
            PolicyName=f'{role_name}Policy',
            PolicyDocument=json.dumps(policy_document)
        )
        policy_arn = policy_response['Policy']['Arn']
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        logger.info(f"Policy '{policy_arn}' attached to role '{role_name}'.")

        return role_arn
    except ClientError as e:
        logger.error(f"Error creating IAM role or attaching policy: {e}")
        raise

def get_secret(secret_name):
    try:
        response = secretsmanager_client.get_secret_value(SecretId=secret_name)
        return response['SecretString']
    except ClientError as e:
        logger.error(f"Error retrieving secret: {e}")
        raise

def create_codebuild_project(project_name, role_arn, s3_bucket):
    try:
        codebuild_client.create_project(
            name=project_name,
            source={
                'type': 'GITHUB',
                'location': f'https://github.com/myorg/{REPO_NAME}.git'
            },
            artifacts={
                'type': 'S3',
                'location': s3_bucket
            },
            environment={
                'type': 'LINUX_CONTAINER',
                'computeType': 'BUILD_GENERAL1_SMALL',
                'image': 'aws/codebuild/standard:5.0'
            },
            serviceRole=role_arn
        )
        logger.info(f"CodeBuild project '{project_name}' created.")
    except ClientError as e:
        logger.error(f"Error creating CodeBuild project: {e}")
        raise

def create_codepipeline():
    try:
        github_oauth_token = get_secret(GITHUB_OAUTH_SECRET_NAME)
        account_id = sts_client.get_caller_identity()['Account']

        pipeline_json = {
            "pipeline": {
                "name": PIPELINE_NAME,
                "roleArn": f"arn:aws:iam::{account_id}:role/{PIPELINE_ROLE_NAME}",
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
                    },
                    # Additional stages can be added here
                ]
            }
        }

        codepipeline_client.create_pipeline(pipeline=pipeline_json)
        logger.info(f"CodePipeline '{PIPELINE_NAME}' created.")
    except ClientError as e:
        logger.error(f"Error creating CodePipeline: {e}")
        if e.response['Error']['Code'] == 'PipelineNameInUseException':
            logger.error("Pipeline name is already in use.")
        raise

def cleanup_resources():
    try:
        delete_s3_bucket(BUCKET_NAME)
        logger.info("Resources cleaned up successfully.")
    except Exception as e:
        logger.error(f"Error during resource cleanup: {e}")
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
                    "Resource": [
                        f"arn:aws:s3:::{BUCKET_NAME}/*",
                        f"arn:aws:logs:{AWS_REGION}:{sts_client.get_caller_identity()['Account']}:log-group:/aws/codebuild/*"
                    ]
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
