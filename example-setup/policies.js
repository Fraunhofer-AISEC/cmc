// Parse the verification result
var obj = JSON.parse(json);

var success = true;

// Basic checks
if (obj.type != "Verification Result") {
    console.log("Invalid type");
    success = false;
}
if (!obj.raSuccessful) {
    console.log("Attestation not sucessful")
    success = false;
}

// Check a certain certificate property in the RTM Manifest
var found = false
for (var i = 0; i < obj.rtmValidation.signatureValidation.length; i++) {
    if (obj.rtmValidation.signatureValidation[i].commonName == "CMC Test Leaf Certificate") {
        found = true;
    }
}
if (!found) {
    console.log("Failed to find certificate 'CMC Test Leaf Certificate'");
    success = false;
}

success