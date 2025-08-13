// Parse the verification result
var obj = JSON.parse(json);

var success = true;

//Generic function for checking roles in SignatureResults
function checkRoles(signatureResults, expectedRoles){
	if (signatureResults.length != expectedRoles.length) {
    console.log("[PolicyEngine] Number of expected roles does not match number of signatures")
    return false;
	}

	for (i = 0; i < signatureResults.length; i++) {
		if (signatureResults[i].certs.length == 0) {
    		console.log("[PolicyEngine] Cert chain for signed artifact is empty")
    		return false;
		}

		if (signatureResults[i].certs.length == 0) {
    		console.log("[PolicyEngine] No validated cert chain provided for signed artifact")
    		return false;
		}

		if (signatureResults[i].certs[0].length == 0) {
    		console.log("[PolicyEngine] Cert chain for signed artifact is empty")
    		return false;
		}

		//initial cert should be the same in each chain if multiple validated chains are provided -> it is sufficient to verify the role in certs[0][0]
		if (signatureResults[i].certs[0][0].subject.organizationalUnit != expectedRoles[i]){
 			console.log("[PolicyEngine] Role " + i + " in cert does not match: " + signatureResults[i].certs[0][0].subject.organizationalUnit + " vs. " + expectedRoles[i])
   		return false;
		}
	}
	return true;
}

//Verify AR was signed by a device
if (!checkRoles(obj.reportSignatureCheck, ["device"])) {
    console.log("[PolicyEngine] Role check for Attestation Report Signature failed")
    success = false;
} else {
	console.log("[PolicyEngine] Role check for Attestation Report Signature successful")
}

//Verify roles used to sign manifests
for (i=0; i < obj.metadata.manifestResults.length; i++){
	if (!checkRoles(obj.metadata.manifestResults[i].signatureValidation, ["Developer", "Evaluator", "Certifier"])) {
		console.log("[PolicyEngine] Role check for Manifest Signature", obj.metadata.manifestResults[i].name, "failed")
		success = false;
	} else {
		console.log("[PolicyEngine] Role check for Manifest Signature successful")
	}
}

//Verify roles used to sign Company Description
if (obj.metadata.compDescResult) {
	if (!checkRoles(obj.metadata.compDescResult.signatureValidation, ["Operator", "Evaluator", "Certifier"])) {
		console.log("[PolicyEngine] Role check for Company Description Signatures failed")
		success = false;
	} else {
		console.log("[PolicyEngine] Role check for Company Description Signatures successful")
	}
} else {
	console.log("[PolicyEngine] Company description not present")
	success = false
}

success
