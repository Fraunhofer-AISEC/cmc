// Parse the verification result
var obj = JSON.parse(json);

var success = true;

// Basic checks
if (obj.type != "Verification Result") {
    console.log("[PolicyEngine] Invalid type");
    success = false;
}
if (obj.summary.status != "success") {
    console.log("[PolicyEngine] Attestation not successful")
    success = false;
}

// Check a certain certificate property in the RTM Manifest
var found = false
for (var i = 0; i < obj.metadata.devDescResult.signatureValidation.length; i++) {
	for (var j = 0; j < obj.metadata.devDescResult.signatureValidation[i].certs.length; j++) {
		for (var k = 0; k < obj.metadata.devDescResult.signatureValidation[i].certs[j].length; k++) {
			if (obj.metadata.devDescResult.signatureValidation[i].certs[j][k].subject.commonName == "CMC Test Leaf Certificate") {
				found = true;
			}
		}
	}
}
if (!found) {
    console.log("[PolicyEngine] Failed to find certificate 'CMC Test Leaf Certificate'");
    success = false;
}

success
