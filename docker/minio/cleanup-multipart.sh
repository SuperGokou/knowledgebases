#!/bin/sh
set -eu

: "${MINIO_ENDPOINT:?MINIO_ENDPOINT is required}"
: "${MINIO_ROOT_USER:?MINIO_ROOT_USER is required}"
: "${MINIO_ROOT_PASSWORD:?MINIO_ROOT_PASSWORD is required}"
: "${MINIO_BUCKET:?MINIO_BUCKET is required}"

MC_CONFIG_DIR="${MC_CONFIG_DIR:-/tmp/.mc}"
export MC_CONFIG_DIR

max_age="${MINIO_MULTIPART_MAX_AGE:-2d}"
interval="${MINIO_MULTIPART_CLEANUP_INTERVAL_SECONDS:-86400}"

until mc alias set local \
    "${MINIO_ENDPOINT}" \
    "${MINIO_ROOT_USER}" \
    "${MINIO_ROOT_PASSWORD}" \
    --api S3v4 \
    --path on >/dev/null 2>&1; do
    sleep 2
done

# MinIO's generic expiration rule also expires completed objects on an
# unversioned bucket. Restrict cleanup to incomplete multipart data so valid
# knowledge-base files are never selected. In production, run this same command
# from a Kubernetes CronJob or an equivalent scheduler instead of this loop.
while :; do
    echo "Removing incomplete multipart uploads older than ${max_age}"
    if ! mc rm \
        --incomplete \
        --recursive \
        --force \
        --older-than "${max_age}" \
        "local/${MINIO_BUCKET}"; then
        echo "Multipart cleanup failed; the next scheduled run will retry" >&2
    fi
    echo "Removing completed staging objects older than ${max_age}"
    if ! mc rm \
        --recursive \
        --force \
        --older-than "${max_age}" \
        "local/${MINIO_BUCKET}/staging/"; then
        echo "Staging-object cleanup failed; the next scheduled run will retry" >&2
    fi
    sleep "${interval}"
done
