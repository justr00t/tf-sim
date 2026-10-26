package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/boomer/tf-sim/internal/model"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/zclconf/go-cty/cty"
)

// LoadProviderSchemas reads and parses a terraform providers schema -json file.
func (p *Parser) LoadProviderSchemas(ctx context.Context, schemaPath string) (model.ProviderSchemaMap, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fi, err := os.Stat(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("stat schema file %s: %w", schemaPath, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("path is a directory, not a file: %s", schemaPath)
	}
	f, err := os.Open(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("open schema file %s: %w", schemaPath, err)
	}
	defer f.Close()

	return p.LoadProviderSchemasReader(ctx, f)
}

// LoadProviderSchemasReader parses provider schemas from an io.Reader.
func (p *Parser) LoadProviderSchemasReader(ctx context.Context, r io.Reader) (model.ProviderSchemaMap, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read schema data: %w", err)
	}

	var ps tfjson.ProviderSchemas
	if err := json.Unmarshal(data, &ps); err != nil {
		return nil, fmt.Errorf("unmarshal provider schemas: %w", err)
	}

	result := make(model.ProviderSchemaMap)
	if ps.Schemas == nil {
		return result, nil
	}

	for _, provSchema := range ps.Schemas {
		if provSchema == nil || provSchema.ResourceSchemas == nil {
			continue
		}
		for resType, resSchema := range provSchema.ResourceSchemas {
			if resSchema == nil || resSchema.Block == nil {
				continue
			}
			result[resType] = convertBlockToResourceSchema(resType, resSchema.Block)
		}
	}

	return result, nil
}

func convertBlockToResourceSchema(resourceType string, block *tfjson.SchemaBlock) model.ResourceSchema {
	res := model.ResourceSchema{
		ResourceType: resourceType,
		Attributes:   make(map[string]model.AttributeDef),
		NestedBlocks: make(map[string]model.ResourceSchema),
	}
	if block == nil {
		return res
	}

	for name, attr := range block.Attributes {
		if attr == nil {
			continue
		}
		res.Attributes[name] = model.AttributeDef{
			Name:     name,
			Type:     resolveAttributeType(attr),
			Optional: attr.Optional,
			Required: attr.Required,
			Computed: attr.Computed,
		}

		// If the attribute contains nested attributes (AttributeNestedType),
		// map them into res.NestedBlocks for hierarchical AST verification.
		if attr.AttributeNestedType != nil && len(attr.AttributeNestedType.Attributes) > 0 {
			res.NestedBlocks[name] = convertNestedAttrToResourceSchema(name, attr.AttributeNestedType)
		}
	}

	for blockName, blockType := range block.NestedBlocks {
		if blockType == nil || blockType.Block == nil {
			continue
		}
		res.NestedBlocks[blockName] = convertBlockToResourceSchema(blockName, blockType.Block)
	}

	return res
}

func convertNestedAttrToResourceSchema(name string, nat *tfjson.SchemaNestedAttributeType) model.ResourceSchema {
	nested := model.ResourceSchema{
		ResourceType: name,
		Attributes:   make(map[string]model.AttributeDef),
		NestedBlocks: make(map[string]model.ResourceSchema),
	}
	if nat == nil {
		return nested
	}
	for subName, subAttr := range nat.Attributes {
		if subAttr == nil {
			continue
		}
		nested.Attributes[subName] = model.AttributeDef{
			Name:     subName,
			Type:     resolveAttributeType(subAttr),
			Optional: subAttr.Optional,
			Required: subAttr.Required,
			Computed: subAttr.Computed,
		}
		if subAttr.AttributeNestedType != nil && len(subAttr.AttributeNestedType.Attributes) > 0 {
			nested.NestedBlocks[subName] = convertNestedAttrToResourceSchema(subName, subAttr.AttributeNestedType)
		}
	}
	return nested
}

func resolveAttributeType(attr *tfjson.SchemaAttribute) string {
	if attr == nil {
		return "unknown"
	}
	if attr.AttributeNestedType != nil {
		switch attr.AttributeNestedType.NestingMode {
		case tfjson.SchemaNestingModeSingle, tfjson.SchemaNestingModeGroup:
			return "object"
		case tfjson.SchemaNestingModeList, tfjson.SchemaNestingModeSet:
			return "list"
		case tfjson.SchemaNestingModeMap:
			return "map"
		default:
			return "object"
		}
	}
	t := attr.AttributeType
	if t == cty.NilType {
		return "unknown"
	}
	switch {
	case t.Equals(cty.String):
		return "string"
	case t.Equals(cty.Bool):
		return "bool"
	case t.Equals(cty.Number):
		return "number"
	case t.IsListType() || t.IsSetType() || t.IsTupleType():
		return "list"
	case t.IsMapType():
		return "map"
	case t.IsObjectType():
		return "object"
	default:
		return t.FriendlyName()
	}
}
