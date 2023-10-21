package stores

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/kod2ulz/gostart/collections"
	"github.com/kod2ulz/gostart/logr"
	"github.com/kod2ulz/gostart/object"
	"github.com/kod2ulz/gostart/utils"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/pkg/errors"
)

var (
	env              = utils.Env.Helper("MINIO_STORAGE")
	MINIO_USE_SSL    = env.Get("USE_SSL", "true").Bool()
	MINIO_ACCESS_KEY = env.Get("ACCESS_KEY", "invalid-minio-key").String()
	MINIO_SECRET_KEY = env.Get("SECRET_KEY", "invalid-minio-key").String()
	MINIO_ENDPOINT   = env.Get("ENDPOINT", "minio.example.dev").String()
	MINIO_TIMEOUT    = env.Get("TIMEOUT", "10s").Duration()
)

func Minio(log *logr.Logger) (out *MinioClient) {
	refreshConfig()
	client, err := minio.New(MINIO_ENDPOINT, &minio.Options{
		Creds:  credentials.NewStaticV4(MINIO_ACCESS_KEY, MINIO_SECRET_KEY, ""),
		Secure: MINIO_USE_SSL,
	})
	utils.Error.Fail(log.Entry, err, "failed to initialise minio client")
	log.Info("initialised minio client")
	return &MinioClient{Client: client, log: log}
}

func refreshConfig() {
	MINIO_USE_SSL = env.Get("USE_SSL", "true").Bool()
	MINIO_ACCESS_KEY = env.Get("ACCESS_KEY", "invalid-minio-key").String()
	MINIO_SECRET_KEY = env.Get("SECRET_KEY", "invalid-minio-key").String()
	MINIO_ENDPOINT = env.Get("ENDPOINT", "minio.example.dev").String()
	MINIO_TIMEOUT = env.Get("TIMEOUT", "10s").Duration()
}

type MinioClient struct {
	log *logr.Logger
	*minio.Client
}

// ObjectReaderFunc expects you to handle the closing yourself
type ObjectReaderFunc func(int64, string, io.ReadCloser) error

func (c *MinioClient) SaveToTemp(ctx context.Context, bucket, key string, parentDirs ...string) (path string, err error) {
	err = c.StreamObject(ctx, bucket, key, func(size int64, filename string, reader io.ReadCloser) error {
		var tmpFile *os.File
		dir := strings.Join(append(append([]string{os.TempDir()}, parentDirs...), bucket), string(os.PathSeparator))
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return errors.Wrapf(err, "failed to create parent directory '%s' for object %s/%s", dir, bucket, key)
		}
		path = strings.Join([]string{dir, key}, string(os.PathSeparator))
		if tmpFile, err = os.Create(path); err != nil {
			return errors.Wrapf(err, "error creating temp file at %s", path)
		}
		defer tmpFile.Close()
		if _, err = io.CopyN(tmpFile, reader, size); err != nil {
			return errors.Errorf("failed to write %s/%s to %s", bucket, key, path)
		}
		return err
	})
	return
}

func (c *MinioClient) StreamObject(ctx context.Context, bucket, key string, out ObjectReaderFunc) (err error) {
	var reader *minio.Object
	var info minio.ObjectInfo
	if reader, err = c.GetObject(ctx, bucket, key, minio.GetObjectOptions{}); err != nil {
		return errors.Wrapf(err, "error fetching object %s from bucket %s", key, bucket)
	} else if reader == nil {
		return errors.Errorf("object %s/%s returned empty object from storage", bucket, key)
	}
	// defer reader.Close()
	if info, err = reader.Stat(); err != nil {
		return errors.Errorf("failed to stat file retrieved from %s/%s", bucket, key)
	} else if info.Size == 0 {
		return errors.Errorf("object %s/%s returned empty object from storage", bucket, key)
	}
	var filename string = object.String(key).Split("/").Last()
	return out(info.Size, filename, reader)
}

func (c *MinioClient) StreamObjects(ctx context.Context, urls []string, out ObjectReaderFunc) (err error) {
	if len(urls) == 0 {
		return
	}
	buckets := urlsToBucketKeyGroups(urls...)
	if len(buckets) == 0 {
		return
	}
	for bucket, keys := range buckets {
		for _, key := range keys {
			if err = c.StreamObject(ctx, bucket, key, out); err != nil {
				return errors.Wrapf(err, "encoundered error streaming %s/%s", bucket, key)
			}
		}
	}
	return
}

func urlsToBucketKeyGroups(urls ...string) (out map[string][]string) {
	if len(urls) == 0 {
		return
	}
	out = make(map[string][]string)
	for i := range urls {
		var parts collections.List[string]
		if endpoint := urls[i]; endpoint == "" || !strings.Contains(endpoint, "/") {
			continue
		} else if parts = strings.Split(endpoint, "/"); parts.Size() < 2 {
			continue
		}
		bucket, key := parts.First(), strings.Join(parts[1:], "/")
		if _, ok := out[bucket]; !ok {
			out[bucket] = make([]string, 0)
		}
		out[bucket] = append(out[bucket], key)
	}
	return
}
