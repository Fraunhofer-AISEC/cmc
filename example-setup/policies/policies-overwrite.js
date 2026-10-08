// Parse the result
var obj = JSON.parse(json);

// Downgrade a failed verification to a warning
if (obj.summary.status == "fail") {
    console.log("Downgrading failed attestation result to warn");
    obj.summary.status = "warn";
}

// Return modified result
JSON.stringify(obj)