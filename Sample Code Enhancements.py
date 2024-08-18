Sample Code Enhancementsdef create_s3_bucket(bucket_name):
    try:
        if s3_client.head_bucket(Bucket=bucket_name):
            logger.info(f"S3 bucket '{bucket_name}' already exists.")
            return
        
        # Create the S3 bucket
        s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={'LocationConstraint': AWS_REGION}
        )
        logger.info(f"S3 bucket '{bucket_name}' created.")
        ...
