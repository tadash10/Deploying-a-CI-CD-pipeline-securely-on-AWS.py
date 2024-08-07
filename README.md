# Deploying-a-CI-CD-pipeline-securely-on-AWS


Deploying a CI/CD pipeline securely on AWS from the CLI involves several steps, including setting up your environment, configuring AWS services, and ensuring security best practices.

For this script, I'll provide a Python script that utilizes the AWS CLI to set up a CI/CD pipeline using AWS CodePipeline, AWS CodeBuild, and other necessary AWS resources. The script will handle the creation of resources like CodePipeline, CodeBuild projects, S3 buckets for artifacts, and IAM roles with appropriate policies.

AWS CI/CD Pipeline Setup

This repository provides a Python script to set up an AWS CI/CD pipeline using AWS CodePipeline, CodeBuild, IAM roles, and S3. The script includes security best practices such as least privilege IAM roles, secure secrets management, and S3 bucket encryption.
Features

    Creates an S3 bucket for storing pipeline artifacts.
    Sets up IAM roles and policies with the principle of least privilege.
    Configures a CodeBuild project with the required role and permissions.
    Creates a CodePipeline with source, build, and deployment stages.
    Uses AWS Secrets Manager for secure storage of sensitive information.

Prerequisites

    AWS CLI configured with the necessary permissions.
    Python 3.x installed.
    Boto3 library installed (pip install boto3).

Setup Instructions
1. Clone the Repository
2.
3.         git clone https://github.com/your-repo/aws-ci-cd-pipeline-setup.git
           cd aws-ci-cd-pipeline-setup

2. Update Configuration

Edit the Python script pipeline_setup.py to replace placeholder values with your actual configuration:

    AWS_REGION: Your AWS region.
    PIPELINE_NAME: Name of your CodePipeline.
    REPO_NAME: Name of your GitHub repository.
    BUCKET_NAME: Name of your S3 bucket.
    CODEBUILD_ROLE_NAME: Name for the CodeBuild IAM role.
    PIPELINE_ROLE_NAME: Name for the CodePipeline IAM role.
    SOURCE_STAGE_NAME, BUILD_STAGE_NAME, DEPLOY_STAGE_NAME: Names of the stages in your pipeline.
    GITHUB_OAUTH_SECRET_NAME: Name of the GitHub OAuth token secret in AWS Secrets Manager.

3. Install Python Dependencies

Ensure you have the required Python packages:

bash

pip install boto3

4. Run the Script

Execute the script to set up the AWS CI/CD pipeline:

bash

      python pipeline_setup.py

CLI Commands

Here are the AWS CLI commands used in the script, which you can run manually if needed.
Create an S3 Bucket

bash

          aws s3api create-bucket --bucket your-bucket-name --region your-region --create-bucket-configuration LocationConstraint=your-region

Set S3 Bucket Policy

bash

aws s3api put-bucket-policy --bucket your-bucket-name --policy '{"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::your-bucket-name/*", "Condition": {"Bool": {"aws:PublicAccess": "true"}}}, {"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::your-bucket-name/*"], "Condition": {"StringEquals": {"aws:userid": "CodePipeline and CodeBuild"}}]}'

Enable Server-Side Encryption

bash

              aws s3api put-bucket-encryption --bucket your-bucket-name --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'

Create IAM Role

bash

             aws iam create-role --role-name your-role-name --assume-role-policy-document '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'

Attach IAM Policy

bash

aws iam put-role-policy --role-name your-role-name --policy-name your-policy-name --policy-document '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "s3:GetObject", "s3:PutObject"], "Resource": "*"}]}'

Create CodeBuild Project

bash

aws codebuild create-project --name your-project-name --source type=GITHUB,location=https://github.com/yourorg/your-repo.git --artifacts type=S3,location=your-bucket-name --environment type=LINUX_CONTAINER,computeType=BUILD_GENERAL1_SMALL,image=aws/codebuild/standard:5.0 --service-role arn:aws:iam::your-account-id:role/your-role-name --region your-region

Create CodePipeline

bash

aws codepipeline create-pipeline --cli-input-json '{"pipeline": {"name": "your-pipeline-name", "roleArn": "arn:aws:iam::your-account-id:role/your-role-name", "artifactStore": {"type": "S3", "location": "your-bucket-name"}, "stages": [{"name": "Source", "actions": [{"name": "SourceAction", "actionTypeId": {"category": "Source", "owner": "ThirdParty", "provider": "GitHub", "version": "1"}, "outputArtifacts": [{"name": "SourceArtifact"}], "configuration": {"Owner": "your-org", "Repo": "your-repo", "Branch": "main", "OAuthToken": "your-oauth-token"}, "runOrder": 1}]}, {"name": "Build", "actions": [{"name": "BuildAction", "actionTypeId": {"category": "Build", "owner": "AWS", "provider": "CodeBuild", "version": "1"}, "inputArtifacts": [{"name": "SourceArtifact"}], "outputArtifacts": [{"name": "BuildArtifact"}], "configuration": {"ProjectName": "your-project-name"}, "runOrder": 1}]}]}}'

Security Considerations

    Regularly review IAM policies and roles for least privilege.
    Rotate secrets and credentials periodically.
    Monitor and log all activities for security auditing.

Troubleshooting

    Ensure AWS CLI is properly configured with appropriate permissions.
    Verify that all required Python packages are installed.
    Check AWS CloudTrail logs for detailed error messages if something goes wrong.

Bash CLI Installation and Usage

Here's how you can create a CLI to install and use the Python script:

    Create the Bash Script (install_and_run.sh)

bash

#!/bin/bash

# Variables
SCRIPT_NAME="pipeline_setup.py"
REPO_URL="https://github.com/your-repo/aws-ci-cd-pipeline-setup.git"

# Install Python and dependencies
echo "Installing Python dependencies..."
pip install boto3

# Clone the repository
                  echo "Cloning the repository..."
                  git clone $REPO_URL
                cd aws-ci-cd-pipeline-setup

# Run the Python script
echo "Running the setup script..."
python $SCRIPT_NAME

echo "Pipeline setup complete."

    Make the Script Executable

bash

chmod +x install_and_run.sh

    Run the Bash Script

bash

./install_and_run.sh

AWS CLI Instructions

Ensure that your AWS CLI is properly configured with the necessary credentials and permissions:

    Configure AWS CLI

bash

aws configure

    Verify Configuration

bash

aws sts get-caller-identity

This will return your AWS account details, confirming that your CLI is properly configured.

By following these instructions, you should be able to set up your AWS CI/CD pipeline securely and efficiently. If you have any questions or issues, refer to the troubleshooting section or consult AWS documentation for additional help.



Before running this script, ensure you have the AWS CLI installed and configured with the necessary permissions.
