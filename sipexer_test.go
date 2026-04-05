package main

import (
	"encoding/base64"
	"regexp"
	"testing"
)

func TestPrepareTemplateFieldsUnsetRPort(t *testing.T) {
	savedCliops := cliops
	savedParamFields := paramFields
	savedParamFieldsUnset := paramFieldsUnset
	savedIVarMap := iVarMap
	defer func() {
		cliops = savedCliops
		paramFields = savedParamFields
		paramFieldsUnset = savedParamFieldsUnset
		iVarMap = savedIVarMap
	}()

	cliops = CLIOptions{
		noval: "no",
	}
	paramFields = make(paramFieldsType)
	paramFieldsUnset = make(paramFieldsUnsetType)
	iVarMap = make(iVarMapType)
	paramFieldsUnset["rport"] = true

	tplfields := make(map[string]any)
	SIPExerPrepareTemplateFields(tplfields)

	if got := tplfields["rport"]; got != "" {
		t.Fatalf("expected rport to be unset (empty string), got: %#v", got)
	}
}

func TestPrepareTemplateFieldsUnsetVBranch(t *testing.T) {
	savedCliops := cliops
	savedParamFields := paramFields
	savedParamFieldsUnset := paramFieldsUnset
	savedIVarMap := iVarMap
	defer func() {
		cliops = savedCliops
		paramFields = savedParamFields
		paramFieldsUnset = savedParamFieldsUnset
		iVarMap = savedIVarMap
	}()

	cliops = CLIOptions{
		noval: "no",
	}
	paramFields = make(paramFieldsType)
	paramFieldsUnset = make(paramFieldsUnsetType)
	iVarMap = make(iVarMapType)
	paramFieldsUnset["viabranch"] = true

	tplfields := make(map[string]any)
	SIPExerPrepareTemplateFields(tplfields)

	if got := tplfields["viabranch"]; got != "" {
		t.Fatalf("expected viabranch to be unset (empty string), got: %#v", got)
	}
}

func TestPrepareTemplateFieldsUnsetWinsOverFieldVal(t *testing.T) {
	savedCliops := cliops
	savedParamFields := paramFields
	savedParamFieldsUnset := paramFieldsUnset
	savedIVarMap := iVarMap
	defer func() {
		cliops = savedCliops
		paramFields = savedParamFields
		paramFieldsUnset = savedParamFieldsUnset
		iVarMap = savedIVarMap
	}()

	cliops = CLIOptions{
		noval: "no",
	}
	paramFields = make(paramFieldsType)
	paramFieldsUnset = make(paramFieldsUnsetType)
	iVarMap = make(iVarMapType)
	paramFields["viabranch"] = "custom-branch"
	paramFieldsUnset["viabranch"] = true

	tplfields := make(map[string]any)
	SIPExerPrepareTemplateFields(tplfields)

	if got := tplfields["viabranch"]; got != "" {
		t.Fatalf("expected viabranch to be unset even when field-val is set, got: %#v", got)
	}
}

func TestPrepareTemplateFieldsNoValBehaviorUnchanged(t *testing.T) {
	savedCliops := cliops
	savedParamFields := paramFields
	savedParamFieldsUnset := paramFieldsUnset
	savedIVarMap := iVarMap
	defer func() {
		cliops = savedCliops
		paramFields = savedParamFields
		paramFieldsUnset = savedParamFieldsUnset
		iVarMap = savedIVarMap
	}()

	cliops = CLIOptions{
		noval: "skip",
	}
	paramFields = make(paramFieldsType)
	paramFieldsUnset = make(paramFieldsUnsetType)
	iVarMap = make(iVarMapType)
	paramFields["rport"] = "skip"
	paramFields["date"] = "skip"

	tplfields := make(map[string]any)
	SIPExerPrepareTemplateFields(tplfields)

	if got := tplfields["rport"]; got != "" {
		t.Fatalf("expected rport to be empty when set to no-val marker, got: %#v", got)
	}
	if _, ok := tplfields["date"]; ok {
		t.Fatalf("expected date to be removed when set to no-val marker")
	}
}

func TestPrepareTemplateFieldsUuidsToken(t *testing.T) {
	savedCliops := cliops
	savedParamFields := paramFields
	savedParamFieldsUnset := paramFieldsUnset
	savedIVarMap := iVarMap
	defer func() {
		cliops = savedCliops
		paramFields = savedParamFields
		paramFieldsUnset = savedParamFieldsUnset
		iVarMap = savedIVarMap
	}()

	cliops = CLIOptions{
		fieldseval: true,
		noval:      "no",
	}
	paramFields = make(paramFieldsType)
	paramFieldsUnset = make(paramFieldsUnsetType)
	iVarMap = make(iVarMapType)

	tplfields := map[string]any{
		"token": "$uuids",
	}
	SIPExerPrepareTemplateFields(tplfields)

	encoded, ok := tplfields["token"].(string)
	if !ok || len(encoded) == 0 {
		t.Fatalf("expected $uuids to evaluate to non-empty string, got: %#v", tplfields["token"])
	}
	if regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(encoded) == false {
		t.Fatalf("expected base64url characters only, got: %q", encoded)
	}
	if regexp.MustCompile(`=`).MatchString(encoded) {
		t.Fatalf("expected no padding in base64url output, got: %q", encoded)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("expected valid raw base64url string, got error: %v", err)
	}
	if len(decoded) != 16 {
		t.Fatalf("expected decoded UUID size to be 16 bytes, got: %d", len(decoded))
	}
}

func TestPrepareTemplateFieldsUuidTokenStillWorks(t *testing.T) {
	savedCliops := cliops
	savedParamFields := paramFields
	savedParamFieldsUnset := paramFieldsUnset
	savedIVarMap := iVarMap
	defer func() {
		cliops = savedCliops
		paramFields = savedParamFields
		paramFieldsUnset = savedParamFieldsUnset
		iVarMap = savedIVarMap
	}()

	cliops = CLIOptions{
		fieldseval: true,
		noval:      "no",
	}
	paramFields = make(paramFieldsType)
	paramFieldsUnset = make(paramFieldsUnsetType)
	iVarMap = make(iVarMapType)

	tplfields := map[string]any{
		"token": "$uuid",
	}
	SIPExerPrepareTemplateFields(tplfields)

	uuidString, ok := tplfields["token"].(string)
	if !ok || len(uuidString) != 36 {
		t.Fatalf("expected standard UUID string with 36 chars, got: %#v", tplfields["token"])
	}
	if regexp.MustCompile(`^[0-9a-fA-F-]+$`).MatchString(uuidString) == false {
		t.Fatalf("expected canonical UUID text form, got: %q", uuidString)
	}
}
