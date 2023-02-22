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

//Generic function for checking roles in SignatureResults
function checkRoles(signatureResults, expectedRoles){
	if (signatureResults.length != expectedRoles.length) {
    console.log("Number of expected roles does not match number of signatures")
    return false;
	}
		
	for (i = 0; i < signatureResults.length; i++) {
		if (signatureResults[i].validatedCerts.length == 0) {
    		console.log("Cert chain for signed artifact is empty")
    		return false;
		}

		if (signatureResults[i].validatedCerts.length == 0) {
    		console.log("No validated cert chain provided for signed artifact")
    		return false;
		}
		
		if (signatureResults[i].validatedCerts[0].length == 0) {
    		console.log("Cert chain for signed artifact is empty")
    		return false;
		}	
		
		//initial cert should be the same in each chain if multiple validated chains are provided -> it is sufficient to verify the role in validatedCerts[0][0]
		if (signatureResults[i].validatedCerts[0][0].subject.organizationalUnit != expectedRoles[i]){
 			console.log("Role " + i + " in cert does not match: " + signatureResults[i].validatedCerts[0][0].subject.organizationalUnit + " vs. " + expectedRoles[i])
   		return false;
		}
	} 
	return true;
}

//Verify AR was signed by a device
if (!checkRoles(obj.reportSignatureCheck, ["Device"])) {
    console.log("Role check for Attestation Report Signature failed")
    success = false;
} else {
	console.log("Role check for Attestation Report Signature successful")
}

//Verify roles used to sign RTM Manifest
if (!checkRoles(obj.rtmValidation.signatureValidation, ["Developer", "Evaluator", "Certifier"])) {
    console.log("Role check for RTM Manifest Signatures failed")
    success = false;
} else {
	console.log("Role check for RTM Manifest Signature successful")
}


//Verify roles used to sign OS Manifest
if (!checkRoles(obj.osValidation.signatureValidation, ["Developer", "Evaluator", "Certifier"])) {
    console.log("Role check for OS Manifest Signatures failed")
    success = false;
} else {
	console.log("Role check for OS Manifest Signature successful")
}


//Verify roles used to sign App Manifests (if applicable)
if (obj.appValidation) {
	for (i=0; i < obj.appValidation.length; i++){
		if (!checkRoles(obj.appValidation[i].signatureValidation, ["Developer", "Evaluator", "Certifier"])) {
   		console.log("Role check for Signatures of App Manifest " + i + " failed")
   		success = false;
		} else {
			console.log("Role check for Signatures of App Manifest " + i + " successful")
		}
	}	
}

//Verify roles used to sign Company Description
if (!checkRoles(obj.companyValidation.signatureValidation, ["Operator", "Evaluator", "Certifier"])) {
    console.log("Role check for Company Description Signatures failed")
    success = false;
} else {
	console.log("Role check for Company Description Signatures successful")
}

//TODO: Verify that operator who signed the Company Description belongs to the company mentioned in the Company Description

//TODO: Verify the operator who signed the Device Description belongs to the company mentioned in the Company Description

success
