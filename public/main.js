// document.getElementById('login').addEventListener('click', (e) => {
//   let usernameElm = document.getElementById('username');
//   console.log('login clicked:- ', usernameElm.value, e);
//   const username = usernameElm.value;
//   fetch('/api/login', {
//     method: 'POST',
//     credentials: 'include',
//     headers: {
//       'Content-Type': 'application/json',
//     },
//     body: JSON.stringify({ username }),
//   })
//     .then((response) => response.json())
//     .then((response) => {
//       if (response.status != 'ok')
//         throw new Error(
//           `Server responed with error. The message is: ${response.message}`,
//         );

//       return response;
//     })
//     .then((response) => {
//       console.log(response);
//       response.challenge = base64url.decode(response.challenge);
//       for (let allowCred of getAssert.allowCredentials) {
//         allowCred.id = base64url.decode(allowCred.id);
//       }

//       return navigator.credentials.get({ response });
//     })
//     .then((response) => {
//       console.log();
//       let publicKeyCredentialToJSON = (pubKeyCred) => {
//         if (pubKeyCred instanceof Array) {
//           let arr = [];
//           for (let i of pubKeyCred) arr.push(publicKeyCredentialToJSON(i));

//           return arr;
//         }

//         if (pubKeyCred instanceof ArrayBuffer) {
//           return base64url.encode(pubKeyCred);
//         }

//         if (pubKeyCred instanceof Object) {
//           let obj = {};

//           for (let key in pubKeyCred) {
//             obj[key] = publicKeyCredentialToJSON(pubKeyCred[key]);
//           }

//           return obj;
//         }

//         return pubKeyCred;
//       };

//       let getAssertionResponse = publicKeyCredentialToJSON(response);

//       return fetch('/api/response', {
//         method: 'POST',
//         credentials: 'include',
//         headers: {
//           'Content-Type': 'application/json',
//         },
//         body: JSON.stringify(getAssertionResponse),
//       })
//         .then((response) => response.json())
//         .then((response) => {
//           if (response.status != 'ok')
//             throw new Error(
//               `Server responed with error. The message is: ${response.message}`,
//             );

//           return response;
//         });
//     })
//     .then((response) => {
//       if (response.status == 'ok') {
//         console.log('Final login Success:- ', response);
//       } else {
//         alert(
//           `Server responed with error. The message is: ${response.message}`,
//         );
//       }
//     })
//     .catch((error) => {
//       console.log('Login error fiunally:- ', error);
//       alert(error);
//     });
// });

// document.getElementById('register').addEventListener('click', (e) => {
//   let usernameElm = document.getElementById('username');
//   console.log('register clicked:- ', usernameElm.value, e);
//   const username = usernameElm.value;
//   const name = 'sjangir';

//   fetch('/api/register', {
//     method: 'POST',
//     credentials: 'include',
//     headers: {
//       'Content-Type': 'application/json',
//     },
//     body: JSON.stringify({ username, name }),
//   })
//     .then((response) => {
//       return response.json();
//     })
//     .then((response) => {
//       console.log('Register response:- ', response);
//       if (response.status != 'ok') {
//         console.log('Register response inside if condition fail');
//         throw new Error(
//           `Server responed with error. The message is: ${response.message}`,
//         );
//       }

//       return response;
//     })
//     .then((response) => {
//       response.challenge = base64url.decode(response.challenge);
//       response.user.id = base64url.decode(response.user.id);

//       return navigator.credentials.create({ response });
//     })
//     .then((response) => {
//       let publicKeyCredentialToJSON = (pubKeyCred) => {
//         if (pubKeyCred instanceof Array) {
//           let arr = [];
//           for (let i of pubKeyCred) arr.push(publicKeyCredentialToJSON(i));

//           return arr;
//         }

//         if (pubKeyCred instanceof ArrayBuffer) {
//           return base64url.encode(pubKeyCred);
//         }

//         if (pubKeyCred instanceof Object) {
//           let obj = {};

//           for (let key in pubKeyCred) {
//             obj[key] = publicKeyCredentialToJSON(pubKeyCred[key]);
//           }

//           return obj;
//         }

//         return pubKeyCred;
//       };

//       let makeCredResponse = publicKeyCredentialToJSON(response);

//       return fetch('/api/response', {
//         method: 'POST',
//         credentials: 'include',
//         headers: {
//           'Content-Type': 'application/json',
//         },
//         body: JSON.stringify(makeCredResponse),
//       })
//         .then((response) => response.json())
//         .then((response) => {
//           console.log('Response:- ', response);
//           if (response.status != 'ok')
//             throw new Error(
//               `Server responed with error. The message is: ${response.message}`,
//             );

//           return response;
//         });
//     })
//     .then((response) => {
//       if (response.status == 'ok') {
//         console.log('Final Register Success:- ', response);
//       } else {
//         alert(
//           `Server responed with error. The message is: ${response.message}`,
//         );
//       }
//     })
//     .catch((error) => {
//       console.log('Register error:- ', error);
//       alert(error);
//     });
// });

const { startRegistration, startAuthentication } = window.SimpleWebAuthnBrowser;

// <button>
const register = document.getElementById('register');
// <span>/<p>/etc...
const elemSuccess = document.getElementById('success');
// <span>/<p>/etc...
const elemError = document.getElementById('error');

// Start registration when the user clicks a button
register.addEventListener('click', async () => {
  // Reset success/error messages
  elemSuccess.innerHTML = '';
  elemError.innerHTML = '';

  // GET registration options from the endpoint that calls
  // @simplewebauthn/server -> generateRegistrationOptions()
  const resp = await fetch('/generate-registration-options');

  let attResp;
  try {
    // Pass the options to the authenticator and wait for a response
    attResp = await startRegistration(await resp.json());
  } catch (error) {
    // Some basic error handling
    if (error.name === 'InvalidStateError') {
      elemError.innerText =
        'Error: Authenticator was probably already registered by user';
    } else {
      elemError.innerText = error;
    }

    throw error;
  }

  // POST the response to the endpoint that calls
  // @simplewebauthn/server -> verifyRegistrationResponse()
  const verificationResp = await fetch('/verify-registration', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(attResp),
  });

  // Wait for the results of verification
  const verificationJSON = await verificationResp.json();

  // Show UI appropriate for the `verified` status
  if (verificationJSON && verificationJSON.verified) {
    elemSuccess.innerHTML = 'Success!';
  } else {
    elemError.innerHTML = `Oh no, something went wrong! Response: <pre>${JSON.stringify(
      verificationJSON,
    )}</pre>`;
  }
});

/**
 * Login Steps
 */

// <button>
const login = document.getElementById('login');
// Start authentication when the user clicks a button
login.addEventListener('click', async () => {
  // Reset success/error messages
  elemSuccess.innerHTML = '';
  elemError.innerHTML = '';

  // GET authentication options from the endpoint that calls
  // @simplewebauthn/server -> generateAuthenticationOptions()
  const resp = await fetch('/generate-authentication-options');

  let asseResp;
  try {
    // Pass the options to the authenticator and wait for a response
    asseResp = await startAuthentication(await resp.json());
  } catch (error) {
    // Some basic error handling
    elemError.innerText = error;
    throw error;
  }

  // POST the response to the endpoint that calls
  // @simplewebauthn/server -> verifyAuthenticationResponse()
  const verificationResp = await fetch('/verify-authentication', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(asseResp),
  });

  // Wait for the results of verification
  const verificationJSON = await verificationResp.json();

  // Show UI appropriate for the `verified` status
  if (verificationJSON && verificationJSON.verified) {
    elemSuccess.innerHTML = 'Success!';
  } else {
    elemError.innerHTML = `Oh no, something went wrong! Response: <pre>${JSON.stringify(
      verificationJSON,
    )}</pre>`;
  }
});
