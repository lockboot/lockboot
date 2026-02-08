#!/bin/bash
# Script to create the vmimport IAM role required for AWS VM Import/Export
# This is a one-time setup per AWS account
# Usage: ./create-vmimport-role.sh <s3-bucket-name>

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <s3-bucket-name>"
    echo "Example: $0 lockboot"
    exit 1
fi

S3_BUCKET="$1"

echo "Creating vmimport IAM role for S3 bucket: ${S3_BUCKET}"

# Create temporary files with templates
TRUST_POLICY=$(mktemp trust-policy.tmp.XXXXXXXXXX)
ROLE_POLICY=$(mktemp role-policy.tmp.XXXXXXXXXX)
CREATE_OUTPUT=$(mktemp create-output.tmp.XXXXXXXXXX)

# Cleanup temp files on exit
trap "rm -f ${TRUST_POLICY} ${ROLE_POLICY} ${CREATE_OUTPUT}" EXIT

# Create trust policy
cat > "${TRUST_POLICY}" << 'EOF'
{
   "Version": "2012-10-17",
   "Statement": [
      {
         "Effect": "Allow",
         "Principal": { "Service": "vmie.amazonaws.com" },
         "Action": "sts:AssumeRole",
         "Condition": {
            "StringEquals":{
               "sts:Externalid": "vmimport"
            }
         }
      }
   ]
}
EOF

# Create role policy with the specified bucket
cat > "${ROLE_POLICY}" << EOF
{
   "Version": "2012-10-17",
   "Statement": [
      {
         "Effect": "Allow",
         "Action": [
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket"
         ],
         "Resource": [
            "arn:aws:s3:::${S3_BUCKET}",
            "arn:aws:s3:::${S3_BUCKET}/*"
         ]
      },
      {
         "Effect": "Allow",
         "Action": [
            "ec2:ModifySnapshotAttribute",
            "ec2:CopySnapshot",
            "ec2:RegisterImage",
            "ec2:Describe*"
         ],
         "Resource": "*"
      }
   ]
}
EOF

echo ""
echo "Creating IAM role 'vmimport'..."
if aws iam create-role --role-name vmimport --assume-role-policy-document "file://${TRUST_POLICY}" 2>&1 | tee "${CREATE_OUTPUT}" | grep -q "EntityAlreadyExists"; then
    echo "Role 'vmimport' already exists"
else
    echo "Role 'vmimport' created successfully"
fi

echo ""
echo "Attaching role policy..."
aws iam put-role-policy --role-name vmimport --policy-name vmimport --policy-document "file://${ROLE_POLICY}"

echo ""
echo "=== vmimport role setup complete ==="
echo "Role ARN: $(aws iam get-role --role-name vmimport --query 'Role.Arn' --output text)"
echo ""
echo "You can now use create-ami.sh to import disk images from s3://${S3_BUCKET}"
