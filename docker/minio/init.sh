#!/bin/sh
set -eu

: "${MINIO_ENDPOINT:?MINIO_ENDPOINT is required}"
: "${MINIO_ROOT_USER:?MINIO_ROOT_USER is required}"
: "${MINIO_ROOT_PASSWORD:?MINIO_ROOT_PASSWORD is required}"
: "${MINIO_APP_USER:?MINIO_APP_USER is required}"
: "${MINIO_APP_PASSWORD:?MINIO_APP_PASSWORD is required}"
: "${MINIO_BUCKET:?MINIO_BUCKET is required}"

MC_CONFIG_DIR="${MC_CONFIG_DIR:-/tmp/.mc}"
export MC_CONFIG_DIR

attempt=0
until mc alias set local \
    "${MINIO_ENDPOINT}" \
    "${MINIO_ROOT_USER}" \
    "${MINIO_ROOT_PASSWORD}" \
    --api S3v4 \
    --path on >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "${attempt}" -ge 60 ]; then
        echo "MinIO client alias initialization failed; verify the writable client config, DNS, readiness, and credentials" >&2
        exit 1
    fi
    sleep 2
done

mc mb --ignore-existing "local/${MINIO_BUCKET}"
mc anonymous set none "local/${MINIO_BUCKET}"

cat >/tmp/knowledge-app-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"],
      "Resource": ["arn:aws:s3:::${MINIO_BUCKET}"]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": ["arn:aws:s3:::${MINIO_BUCKET}/*"]
    }
  ]
}
EOF

mc admin user add local "${MINIO_APP_USER}" "${MINIO_APP_PASSWORD}" >/dev/null 2>&1 || \
    mc admin user enable local "${MINIO_APP_USER}" >/dev/null
mc admin policy create local knowledge-app /tmp/knowledge-app-policy.json >/dev/null 2>&1 || true
mc admin policy attach local knowledge-app --user "${MINIO_APP_USER}" >/dev/null

echo "MinIO bucket local/${MINIO_BUCKET} is private and the application policy is attached"
