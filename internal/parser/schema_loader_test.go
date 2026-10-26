package parser

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProviderSchemas_MultiCloud(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")

	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("unexpected error loading multicloud schemas: %v", err)
	}

	if len(schemas) != 3 {
		t.Fatalf("expected 3 resource schemas across AWS, Azure, GCP, got %d", len(schemas))
	}

	expectedResources := []string{
		"aws_s3_bucket",
		"azurerm_storage_account",
		"google_storage_bucket",
	}
	for _, resType := range expectedResources {
		if _, exists := schemas[resType]; !exists {
			t.Errorf("expected resource type %q to exist in schemas", resType)
		}
	}
}

func TestLoadProviderSchemas_AWS_Details(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")

	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("unexpected error loading provider schemas: %v", err)
	}

	awsSchema, ok := schemas["aws_s3_bucket"]
	if !ok {
		t.Fatal("expected 'aws_s3_bucket' schema to be present")
	}

	// Verify bucket attribute
	bucketAttr, ok := awsSchema.Attributes["bucket"]
	if !ok {
		t.Fatal("expected 'bucket' attribute in aws_s3_bucket")
	}
	if bucketAttr.Type != "string" {
		t.Errorf("expected bucket type 'string', got %q", bucketAttr.Type)
	}
	if !bucketAttr.Optional {
		t.Error("expected bucket.Optional == true")
	}
	if !bucketAttr.Computed {
		t.Error("expected bucket.Computed == true")
	}

	// Verify arn attribute
	arnAttr, ok := awsSchema.Attributes["arn"]
	if !ok {
		t.Fatal("expected 'arn' attribute in aws_s3_bucket")
	}
	if !arnAttr.Computed {
		t.Error("expected arn.Computed == true")
	}

	// Verify nested blocks: server_side_encryption_configuration -> rule -> apply_server_side_encryption_by_default
	ssecBlock, ok := awsSchema.NestedBlocks["server_side_encryption_configuration"]
	if !ok {
		t.Fatal("expected NestedBlocks['server_side_encryption_configuration']")
	}

	ruleBlock, ok := ssecBlock.NestedBlocks["rule"]
	if !ok {
		t.Fatal("expected NestedBlocks['rule'] under server_side_encryption_configuration")
	}

	applyBlock, ok := ruleBlock.NestedBlocks["apply_server_side_encryption_by_default"]
	if !ok {
		t.Fatal("expected NestedBlocks['apply_server_side_encryption_by_default'] under rule")
	}

	sseAlgorithmAttr, ok := applyBlock.Attributes["sse_algorithm"]
	if !ok {
		t.Fatal("expected 'sse_algorithm' attribute under apply_server_side_encryption_by_default")
	}
	if sseAlgorithmAttr.Type != "string" {
		t.Errorf("expected sse_algorithm type 'string', got %q", sseAlgorithmAttr.Type)
	}
	if !sseAlgorithmAttr.Required {
		t.Error("expected sse_algorithm.Required == true")
	}
}

func TestLoadProviderSchemas_Azure_Details(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")

	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("unexpected error loading provider schemas: %v", err)
	}

	azureSchema, ok := schemas["azurerm_storage_account"]
	if !ok {
		t.Fatal("expected 'azurerm_storage_account' schema to be present")
	}

	// Verify name attribute
	nameAttr, ok := azureSchema.Attributes["name"]
	if !ok {
		t.Fatal("expected 'name' attribute in azurerm_storage_account")
	}
	if !nameAttr.Required {
		t.Error("expected name.Required == true")
	}

	// Verify https_traffic_only_enabled attribute
	httpsAttr, ok := azureSchema.Attributes["https_traffic_only_enabled"]
	if !ok {
		t.Fatal("expected 'https_traffic_only_enabled' attribute")
	}
	if httpsAttr.Type != "bool" {
		t.Errorf("expected https_traffic_only_enabled type 'bool', got %q", httpsAttr.Type)
	}
	if !httpsAttr.Optional {
		t.Error("expected https_traffic_only_enabled.Optional == true")
	}

	// Verify min_tls_version attribute
	tlsAttr, ok := azureSchema.Attributes["min_tls_version"]
	if !ok {
		t.Fatal("expected 'min_tls_version' attribute")
	}
	if tlsAttr.Type != "string" {
		t.Errorf("expected min_tls_version type 'string', got %q", tlsAttr.Type)
	}

	// Verify network_rules nested block
	netBlock, ok := azureSchema.NestedBlocks["network_rules"]
	if !ok {
		t.Fatal("expected 'network_rules' nested block")
	}
	defaultActionAttr, ok := netBlock.Attributes["default_action"]
	if !ok {
		t.Fatal("expected 'default_action' attribute in network_rules")
	}
	if !defaultActionAttr.Required {
		t.Error("expected network_rules.default_action.Required == true")
	}
}

func TestLoadProviderSchemas_GCP_Details(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")

	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("unexpected error loading provider schemas: %v", err)
	}

	gcpSchema, ok := schemas["google_storage_bucket"]
	if !ok {
		t.Fatal("expected 'google_storage_bucket' schema to be present")
	}

	// Verify name attribute
	nameAttr, ok := gcpSchema.Attributes["name"]
	if !ok {
		t.Fatal("expected 'name' attribute in google_storage_bucket")
	}
	if !nameAttr.Required {
		t.Error("expected name.Required == true")
	}

	// Verify uniform_bucket_level_access attribute
	ublaAttr, ok := gcpSchema.Attributes["uniform_bucket_level_access"]
	if !ok {
		t.Fatal("expected 'uniform_bucket_level_access' attribute")
	}
	if ublaAttr.Type != "bool" {
		t.Errorf("expected uniform_bucket_level_access type 'bool', got %q", ublaAttr.Type)
	}

	// Verify encryption nested block
	encBlock, ok := gcpSchema.NestedBlocks["encryption"]
	if !ok {
		t.Fatal("expected 'encryption' nested block in google_storage_bucket")
	}
	kmsAttr, ok := encBlock.Attributes["default_kms_key_name"]
	if !ok {
		t.Fatal("expected 'default_kms_key_name' attribute under encryption")
	}
	if !kmsAttr.Required {
		t.Error("expected default_kms_key_name.Required == true")
	}
}

func TestLoadProviderSchemasReader_EmptySchemas(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	input := `{"format_version":"1.0","provider_schemas":{}}`

	schemas, err := p.LoadProviderSchemasReader(ctx, strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error loading empty provider schemas: %v", err)
	}

	if schemas == nil {
		t.Fatal("expected non-nil schemas map")
	}
	if len(schemas) != 0 {
		t.Errorf("expected 0 schemas, got %d", len(schemas))
	}
}

func TestLoadProviderSchemasReader_DeepNesting(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")

	schemas, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err != nil {
		t.Fatalf("unexpected error loading schema for deep nesting test: %v", err)
	}

	// Test 3+ levels of nested blocks: aws_s3_bucket -> server_side_encryption_configuration -> rule -> apply_server_side_encryption_by_default
	res, ok := schemas["aws_s3_bucket"]
	if !ok {
		t.Fatal("expected 'aws_s3_bucket' schema")
	}

	level1, ok := res.NestedBlocks["server_side_encryption_configuration"]
	if !ok {
		t.Fatal("level 1 block 'server_side_encryption_configuration' missing")
	}

	level2, ok := level1.NestedBlocks["rule"]
	if !ok {
		t.Fatal("level 2 block 'rule' missing")
	}

	level3, ok := level2.NestedBlocks["apply_server_side_encryption_by_default"]
	if !ok {
		t.Fatal("level 3 block 'apply_server_side_encryption_by_default' missing")
	}

	attr, ok := level3.Attributes["sse_algorithm"]
	if !ok {
		t.Fatal("attribute 'sse_algorithm' in level 3 block missing")
	}
	if attr.Type != "string" || !attr.Required {
		t.Errorf("unexpected attribute definition for sse_algorithm: %+v", attr)
	}
}

func TestLoadProviderSchemas_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel context immediately

	p := NewParser()
	schemaPath := filepath.Join("..", "..", "testdata", "schemas", "multicloud_schema.json")

	_, err := p.LoadProviderSchemas(ctx, schemaPath)
	if err == nil {
		t.Fatal("expected error with canceled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected errors.Is(err, context.Canceled), got: %v", err)
	}
}

func TestLoadProviderSchemas_FileNotFound(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	nonExistentPath := filepath.Join("..", "..", "testdata", "schemas", "missing.json")

	_, err := p.LoadProviderSchemas(ctx, nonExistentPath)
	if err == nil {
		t.Fatal("expected error for missing schema file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "stat schema file") {
		t.Errorf("expected ErrNotExist or wrapped stat error, got: %v", err)
	}
}

func TestLoadProviderSchemas_DirectoryPath(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	dirPath := filepath.Join("..", "..", "testdata", "schemas")

	_, err := p.LoadProviderSchemas(ctx, dirPath)
	if err == nil {
		t.Fatal("expected error when passing directory path, got nil")
	}
	if !strings.Contains(err.Error(), "is a directory, not a file") {
		t.Errorf("expected error message to contain 'is a directory, not a file', got: %v", err)
	}
}

func TestLoadProviderSchemas_MalformedJSON(t *testing.T) {
	ctx := context.Background()
	p := NewParser()
	malformed := `{"provider_schemas": "corrupted"`

	_, err := p.LoadProviderSchemasReader(ctx, strings.NewReader(malformed))
	if err == nil {
		t.Fatal("expected error for malformed schema JSON, got nil")
	}
}
