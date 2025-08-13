// Parse the verification result
var obj = JSON.parse(json);

var success = true;

// Basic checks
if (obj.type != "Verification Result") {
    console.log("[PolicyEngine] Invalid type");
    success = false;
}

// Overwrite the result from failed to warning
obj.summary.status = "warn"

var ret = JSON.stringify(obj);

ret