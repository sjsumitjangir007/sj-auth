import { Controller, Get, Post, Render, Req, Res } from '@nestjs/common';
import base64url from 'base64url';
import { AppService } from './app.service';
import { ORIGIN } from './common/constants';
import { WebAuthnUtil } from './webAuthnUtil.service';

import dotenv from 'dotenv';

/**
 * Referance for complete code
 * https://github.com/MasterKale/SimpleWebAuthn/blob/master/example/index.ts
 */

import {
  // Registration
  generateRegistrationOptions,
  verifyRegistrationResponse,
  // Authentication
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  GenerateRegistrationOptionsOpts,
  GenerateAuthenticationOptionsOpts,
  VerifyRegistrationResponseOpts,
  VerifyAuthenticationResponseOpts,
  VerifiedRegistrationResponse,
  VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';

import type {
  RegistrationCredentialJSON,
  AuthenticationCredentialJSON,
  AuthenticatorDevice,
} from '@simplewebauthn/typescript-types';

interface LoggedInUser {
  id: string;
  username: string;
  devices: AuthenticatorDevice[];
  currentChallenge?: string;
}

dotenv?.config();

// ENABLE_CONFORMANCE, ENABLE_HTTPS,
const { RP_ID = 'localhost' } = process.env;

export const rpID = RP_ID;
// export let expectedOrigin = '';
const loggedInUserId = 'internalUserId';
const inMemoryUserDeviceDB: { [loggedInUserId: string]: LoggedInUser } = {
  [loggedInUserId]: {
    id: loggedInUserId,
    username: `user@${rpID}`,
    devices: [],
    /**
     * A simple way of storing a user's current challenge being signed by registration or authentication.
     * It should be expired after `timeout` milliseconds (optional argument for `generate` methods,
     * defaults to 60000ms)
     */
    currentChallenge: undefined,
  },
};

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly webAuthnUtil: WebAuthnUtil,
  ) {}

  @Get()
  @Render('index')
  root() {
    return { message: 'Hello world...', title: 'SJ Auth', theme: 'dark' };
  }

  @Get('generate-registration-options')
  generateRegistration(@Req() req, @Res() res) {
    const user = inMemoryUserDeviceDB[loggedInUserId];

    const {
      /**
       * The username can be a human-readable name, email, etc... as it is intended only for display.
       */
      username,
      devices,
    } = user;

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: 'SimpleWebAuthn Example',
      rpID,
      userID: loggedInUserId,
      userName: username,
      timeout: 60000,
      attestationType: 'none',
      /**
       * Passing in a user's list of already-registered authenticator IDs here prevents users from
       * registering the same device multiple times. The authenticator will simply throw an error in
       * the browser if it's asked to perform registration when one of these ID's already resides
       * on it.
       */
      excludeCredentials: devices.map((dev) => ({
        id: dev.credentialID,
        type: 'public-key',
        transports: dev.transports,
      })),
      /**
       * The optional authenticatorSelection property allows for specifying more constraints around
       * the types of authenticators that users to can use for registration
       */
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required',
      },
      /**
       * Support the two most common algorithms: ES256, and RS256
       */
      supportedAlgorithmIDs: [-7, -257],
    };

    const options = generateRegistrationOptions(opts);

    /**
     * The server needs to temporarily remember this value for verification, so don't lose it until
     * after you verify an authenticator response.
     */
    inMemoryUserDeviceDB[loggedInUserId].currentChallenge = options.challenge;

    res.send(options);
  }

  @Post('verify-registration')
  async verifyRegistration(@Req() req, @Res() res) {
    const body: RegistrationCredentialJSON = req.body;

    const user = inMemoryUserDeviceDB[loggedInUserId];

    const expectedChallenge = user.currentChallenge;

    let verification: VerifiedRegistrationResponse;
    const expectedOrigin = `http://localhost:${3000}`;
    try {
      const opts: VerifyRegistrationResponseOpts = {
        credential: body,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin,
        expectedRPID: rpID,
        requireUserVerification: true,
      };
      verification = await verifyRegistrationResponse(opts);
    } catch (error) {
      const _error = error as Error;
      console.error(_error);
      return res.status(400).send({ error: _error.message });
    }

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;

      const existingDevice = user.devices.find((device) =>
        device.credentialID.equals(credentialID),
      );

      if (!existingDevice) {
        /**
         * Add the returned device to the user's list of devices
         */
        const newDevice: AuthenticatorDevice = {
          credentialPublicKey,
          credentialID,
          counter,
          transports: body.transports,
        };
        user.devices.push(newDevice);
      }
    }

    res.send({ verified });
  }

  @Get('generate-authentication-options')
  generateAuthentication(@Req() req, @Res() res) {
    // You need to know the user by this point
    const user = inMemoryUserDeviceDB[loggedInUserId];

    const opts: GenerateAuthenticationOptionsOpts = {
      timeout: 60000,
      allowCredentials: user.devices.map((dev) => ({
        id: dev.credentialID,
        type: 'public-key',
        transports: dev.transports,
      })),
      userVerification: 'required',
      rpID,
    };

    const options = generateAuthenticationOptions(opts);

    /**
     * The server needs to temporarily remember this value for verification, so don't lose it until
     * after you verify an authenticator response.
     */
    inMemoryUserDeviceDB[loggedInUserId].currentChallenge = options.challenge;

    res.send(options);
  }

  @Post('verify-authentication')
  async verifyAuthentication(@Req() req, @Res() res) {
    const body: AuthenticationCredentialJSON = req.body;

    const user = inMemoryUserDeviceDB[loggedInUserId];

    const expectedChallenge = user.currentChallenge;

    let dbAuthenticator;
    const bodyCredIDBuffer = base64url.toBuffer(body.rawId);
    // "Query the DB" here for an authenticator matching `credentialID`
    for (const dev of user.devices) {
      if (dev.credentialID.equals(bodyCredIDBuffer)) {
        dbAuthenticator = dev;
        break;
      }
    }

    if (!dbAuthenticator) {
      return res
        .status(400)
        .send({ error: 'Authenticator is not registered with this site' });
    }

    let verification: VerifiedAuthenticationResponse;
    const expectedOrigin = `http://localhost:${3000}`;
    try {
      const opts: VerifyAuthenticationResponseOpts = {
        credential: body,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin,
        expectedRPID: rpID,
        authenticator: dbAuthenticator,
        requireUserVerification: true,
      };
      verification = await verifyAuthenticationResponse(opts);
    } catch (error) {
      const _error = error as Error;
      console.error(_error);
      return res.status(400).send({ error: _error.message });
    }

    const { verified, authenticationInfo } = verification;

    if (verified) {
      // Update the authenticator's counter in the DB to the newest count in the authentication
      dbAuthenticator.counter = authenticationInfo.newCounter;
    }

    res.send({ verified });
  }

  @Get('api/isLoggedIn')
  isLoggedIn(@Req() req, @Res() res) {
    if (!AppService.session.loggedIn) {
      return res.send({
        status: 'failed',
      });
    } else {
      return res.send({
        status: 'ok',
      });
    }
  }

  @Get('api/logout')
  logout(@Req() req, @Res() res) {
    AppService.session.loggedIn = false;
    AppService.session.username = undefined;

    return res.send({
      status: 'ok',
    });
  }

  @Get('api/personalInfo')
  personalInfo(@Req() req, @Res() res) {
    if (!AppService.session.loggedIn) {
      return res.send({
        status: 'failed',
        message: 'Access denied',
      });
    } else {
      return res.send({
        status: 'ok',
        name: AppService.db[AppService.session.username].name,
        theSecret: '<img width="250px" src="img/theworstofthesecrets.jpg">',
      });
    }
  }

  @Post('api/register')
  register(@Req() req, @Res() res) {
    console.log('register response:- ', req.body);
    if (
      AppService.db[req.body.username] &&
      AppService.db[req.body.username].register
    ) {
      return res.send({
        status: 'failed',
        message: `Username ${req.body.username} already exists`,
      });
    }
    AppService.db[req.body.username] = {
      name: req.body.name,
      registered: false,
      id: this.webAuthnUtil.randomBase64URLBuffer(),
      authenticators: [],
    };

    // eslint-disable-next-line prettier/prettier
    const challengeMakeCred    = this.webAuthnUtil.generateServerMakeCredRequest(req.body.username, req.body.name, AppService.db[req.body.username].id)
    challengeMakeCred['status'] = 'ok';

    AppService.session.challenge = challengeMakeCred.challenge;
    AppService.session.username = req.body.username;

    return res.send(challengeMakeCred);
  }

  @Post('api/login')
  login(@Req() req, @Res() res) {
    console.log('login response:- ', req.body);
    if (!req.body || !req.body.username) {
      return res.send({
        status: 'failed',
        message: 'Request missing username field!',
      });
    }

    const username = req.body.username;

    if (!AppService.db[username] || !AppService.db[username].registered) {
      return res.send({
        status: 'failed',
        message: `User ${username} does not exist!`,
      });
    }

    const getAssertion = this.webAuthnUtil.generateServerGetAssertion(
      AppService.db[username].authenticators,
    );
    getAssertion['status'] = 'ok';

    AppService.session.challenge = getAssertion.challenge;
    AppService.session.username = username;

    return res.send(getAssertion);
  }

  @Post('api/response')
  res(@Req() req, @Res() res) {
    console.log('res response:- ', req.body);
    if (
      !req.body ||
      !req.body.id ||
      !req.body.rawId ||
      !req.body.response ||
      !req.body.type ||
      req.body.type !== 'public-key'
    ) {
      res.json({
        status: 'failed',
        message:
          'Response missing one or more of id/rawId/response/type fields, or type is not public-key!',
      });

      return;
    }

    const webauthnResp = req.body;
    const clientData = JSON.parse(
      base64url.decode(webauthnResp.response.clientDataJSON),
    );

    /* Check challenge... */
    if (clientData.challenge !== AppService.session.challenge) {
      return res.send({
        status: 'failed',
        message: "Challenges don't match!",
      });
    }

    /* ...and origin */
    if (clientData.origin !== ORIGIN) {
      return res.send({
        status: 'failed',
        message: "Origins don't match!",
      });
    }

    let result;
    if (webauthnResp.response.attestationObject !== undefined) {
      /* This is create cred */
      result =
        this.webAuthnUtil.verifyAuthenticatorAttestationResponse(webauthnResp);

      if (result.verified) {
        AppService.db[AppService.session.username].authenticators.push(
          result.authrInfo,
        );
        AppService.db[AppService.session.username].registered = true;
      }
    } else if (webauthnResp.response.authenticatorData !== undefined) {
      /* This is get assertion */
      result = this.webAuthnUtil.verifyAuthenticatorAssertionResponse(
        webauthnResp,
        AppService.db[AppService.session.username].authenticators,
      );
    } else {
      return res.send({
        status: 'failed',
        message: 'Can not determine type of response!',
      });
    }

    if (result.verified) {
      AppService.session.loggedIn = true;
      return res.send({ status: 'ok' });
    } else {
      return res.send({
        status: 'failed',
        message: 'Can not authenticate signature!',
      });
    }
  }
}
