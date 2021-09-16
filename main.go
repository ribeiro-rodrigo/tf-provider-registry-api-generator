package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/alexflint/go-filemutex"
	"github.com/binxio/gcloudconfig"
	"github.com/docopt/docopt-go"
	"github.com/mollie/tf-provider-registry-api-generator/signing_key"
	"github.com/mollie/tf-provider-registry-api-generator/versions"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

func assertDiscoveryDocument(bucket *storage.BucketHandle) {
	content := make(map[string]string)
	expect := map[string]string{
		"providers.v1": "/v1/providers/",
	}

	p := path.Join(".well-known", "terraform.json")
	err := readJson(bucket, p, &content)
	if err != nil {
		log.Fatalf("could not read content of %s, %s", p, err)
	}

	if !reflect.DeepEqual(expect, content) {
		log.Printf("INFO: writing content to %s", p)
		writeJson(bucket, p, expect)
	} else {
		log.Printf("INFO: discovery document is up-to-date\n")
	}
}

func readJson(bucket *storage.BucketHandle, filename string, object interface{}) error {
	r, err := bucket.Object(filename).NewReader(context.Background())
	if err != nil {
		if err.Error() == "storage: object doesn't exist" {
			return nil
		}
		return fmt.Errorf("ERROR: failed to read file %s, %s", filename, err)
	}
	defer r.Close()
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return fmt.Errorf("ERROR: failed to read content from %s, %s", filename, err)
	}
	err = json.Unmarshal(body, &object)
	if err != nil {
		return fmt.Errorf("ERROR: failed to unmarshal %s, %s", filename, err)
	}

	return nil
}

func readShasums(bucket *storage.BucketHandle, filename string, shasums map[string]string) error {
	r, err := versions.NewFileReader(filename)
	if err != nil {
		if err.Error() == "storage: object doesn't exist" {
			return nil
		}
		return fmt.Errorf("ERROR: failed to read file %s, %s", filename, err)
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			log.Fatalf("ERROR: expected %s to contain 2 fields on each line, found %d", filename, len(fields))
		}
		shasums[fields[1]] = fields[0]
	}
	return nil
}

func writeJson(bucket *storage.BucketHandle, filename string, content interface{}) {
	log.Printf("INFO: writing %s", filename)

	/*w := bucket.Object(filename).NewWriter(context.Background())
	w.ContentType = "application/json"
	w.CacheControl = "no-cache, max-age=60"*/

	filename = "/Users/ribeiro.santos/testes/" + filename

	if _, err := os.Stat(filename); err != nil {
		err = os.MkdirAll(filepath.Dir(filename), os.ModePerm)

		if err != nil {
			log.Fatalf("INFO: failed to create directory %s, %s", filename, err)
		}
	}

	f, err := os.Create(filename)

	if err != nil {
		log.Fatalf("INFO: failed to write in disk %s, %s", filename, err)
	}

	bytes, err := json.Marshal(content)

	if err != nil {
		log.Fatalf("INFO: failed to marshall %s, %s", filename, err)
	}

	_, err = f.Write(bytes)

	if err != nil {
		log.Fatalf("INFO: failed to write %s, %s", filename, err)
	}

	f.Sync()
	f.Close()

	/*if err = w.Close(); err != nil {
		log.Fatalf("INFO: failed to close %s, %s", filename, err)
	} */
}

func writeProviderVersions(bucket *storage.BucketHandle, directory string, newVersions *versions.ProviderVersions) {
	var existing versions.ProviderVersions
	if err := readJson(bucket, path.Join(directory, "versions"), &existing); err != nil {
		log.Fatalf("ERROR: failed to read the %s/versions, %s", directory, err)
	}
	if reflect.DeepEqual(&existing, newVersions) {
		log.Printf("INFO: %s/versions already up-to-date", directory)
		return
	}
	existing.Merge(*newVersions)
	writeJson(bucket, path.Join(directory, "versions"), existing)
}

func writeProviderVersion(bucket *storage.BucketHandle, directory string, version *versions.BinaryMetaData) {
	filename := path.Join(directory, version.Version, "download", version.Os, version.Arch)
	existing := versions.BinaryMetaData{}

	if err := readJson(bucket, filename, &existing); err != nil {
		log.Fatalf("ERROR: failed to read %s, %s", filename, err)
	}

	if existing.Equals(version) {
		log.Printf("INFO: %s is up-to-date", filename)
		return
	}
	writeJson(bucket, filename, version)
}

func WriteAPIDocuments(bucket *storage.BucketHandle, namespace string, binaries versions.BinaryMetaDataList) {
	assertDiscoveryDocument(bucket)

	providerDirectory := path.Join("v1", "providers", namespace)
	providers := binaries.ExtractVersions()

	for _, binary := range binaries {
		writeProviderVersion(bucket, path.Join(providerDirectory, binary.TypeName), &binary)
	}

	for name, versions := range providers {
		writeProviderVersions(bucket, path.Join(providerDirectory, name), versions)
	}

}

type Options struct {
	BucketName            string
	Namespace             string
	Url                   string
	Prefix                string
	Fingerprint           string
	Protocols             string
	UseDefaultCredentials bool
	Help                  bool
	Version               bool
	storage               *storage.Client
	bucket                *storage.BucketHandle
	credentials           *google.Credentials
	mutexFileName         string
	mutex                 *filemutex.FileMutex
	protocols             []string
}

var (
	version       = "dev"
	commit        = "none"
	date          = "unknown"
	builtBy       = "unknown"
	protocolRegex = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
)

func main() {
	var options Options
	usage := `generate terraform provider registry API documents.

Usage:
  tf-provider-registry-api-generator [--use-default-credentials] [--fingerprint FINGERPRINT]  --bucket-name BUCKET --url URL --namespace NAMESPACE [--protocols PROTOCOLS ] --prefix PREFIX
  tf-provider-registry-api-generator version
  tf-provider-registry-api-generator -h | --help

Options:
  --bucket-name BUCKET       - bucket containing the binaries and the website.
  --url URL                  - of the static website.
  --namespace NAMESPACE      - for the providers.
  --prefix PREFIX            - location of the released binaries in the bucket.
  --protocols PROTOCOL       - comma separated list of supported provider protocols by the provider [default: 5.0]
  --fingerprint FINGERPRINT  - of the public key used to sign, defaults to environment variable GPG_FINGERPRINT.
  --use-default-credentials  - instead of the current gcloud configuration.
  -h --help                  - shows this.
`

	arguments, err := docopt.ParseDoc(usage)
	if err != nil {
		log.Fatalf("ERROR: failed to parse command line, %s", err)
	}
	if err = arguments.Bind(&options); err != nil {
		log.Fatalf("ERROR: failed to bind arguments from command line, %s", err)
	}

	if options.Version {
		fmt.Printf("%s\n", version)
		os.Exit(0)
	}

	options.protocols = make([]string, 0)
	for _, p := range strings.Split(options.Protocols, ",") {
		if !protocolRegex.Match([]byte(p)) {
			log.Fatalf("ERROR: %s is not a version number", p)
		}
		options.protocols = append(options.protocols, p)
	}
	if len(options.protocols) == 0 {
		log.Fatalf("ERROR: no protocols specified")
	}

	if options.Fingerprint == "" {
		options.Fingerprint = os.Getenv("GPG_FINGERPRINT")
		if options.Fingerprint == "" {
			log.Fatalf("ERROR: no fingerprint specified")
		}
	}
	options.mutexFileName = fmt.Sprintf("/tmp/tf-registry-generator-%s.lck", options.BucketName)

	if options.UseDefaultCredentials || !gcloudconfig.IsGCloudOnPath() {
		log.Printf("INFO: using default credentials")
		if options.credentials, err = google.FindDefaultCredentials(context.Background(), "https://www.googleapis.com/auth/devstorage.full_control"); err != nil {
			log.Fatalf("ERROR: failed to get default credentials, %s", err)
		}
	} else {
		if options.credentials, err = gcloudconfig.GetCredentials(""); err != nil {
			log.Fatalf("ERROR: failed to get gcloud config credentials, %s", err)
		}
	}

	options.storage, err = storage.NewClient(context.Background(), option.WithCredentials(options.credentials))
	if err != nil {
		log.Fatalf("ERROR: could not create storage client, %s", err)
	}
	defer options.storage.Close()

	options.bucket = options.storage.Bucket(options.BucketName)
	options.mutex, err = filemutex.New(options.mutexFileName)
	if err != nil {
		log.Fatalf("ERROR: failed to create lock file %s, %s", options.mutexFileName, err)
	}
	defer options.mutex.Close()

	err = options.mutex.Lock()
	if err != nil {
		log.Fatalf("ERROR: failed to obtain lock, %s", err)
	}

	signingKey := signing_key.GetPublicSigningKey(options.Fingerprint)
	files := versions.LoadFromLocal(options.Prefix) //versions.LoadFromBucket(options.bucket, options.Prefix)
	if len(files) == 0 {
		log.Fatalf("ERROR: no release files found in %s at %s", options.BucketName, options.Prefix)
	}

	shasums := make(map[string]string, len(files))
	for _, filename := range files {
		if strings.HasSuffix(filename, "SHA256SUMS") {
			err = readShasums(options.bucket, filename, shasums)
			if err != nil {
				log.Fatalf("%s", err)
			}
		}
	}

	binaries := versions.CreateFromFileList(files, options.Url, signingKey, shasums, options.protocols)
	providers := binaries.ExtractVersions()
	if len(providers) == 0 {
		log.Fatalf("ERROR: no terraform provider binaries detected")
	}

	WriteAPIDocuments(options.bucket, options.Namespace, binaries)
}
