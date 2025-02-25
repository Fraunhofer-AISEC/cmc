// Parse the verification result
var obj = JSON.parse(json);

var success = true;

// Basic checks
if (obj.type != "Verification Result") {
    console.log("Invalid type");
    success = false;
}
if (!obj.raSuccessful) {
    console.log("Attestation not successful")
    success = false;
}

// Check a certain certificate property in the RTM Manifest
var found = false
for (var i = 0; i < obj.rtmValidation.signatureValidation.length; i++) {
	for (var j = 0; j < obj.rtmValidation.signatureValidation[i].validatedCerts.length; j++) {
		for (var k = 0; k < obj.rtmValidation.signatureValidation[i].validatedCerts[j].length; k++) {
			if (obj.rtmValidation.signatureValidation[i].validatedCerts[j][k].subject.commonName == "CMC Test Leaf Certificate") {
				found = true;
			}
		}
	}
}
if (!found) {
    console.log("Failed to find certificate 'CMC Test Leaf Certificate'");
    success = false;
}

success
