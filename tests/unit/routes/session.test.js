// Mock dependencies
jest.mock('../../../src/services/storage');
jest.mock('../../../src/services/auth');

const storage = require('../../../src/services/storage');
const auth = require('../../../src/services/auth');
const sessionRoutes = require('../../../src/routes/session');

describe('Session Routes', () => {
  let mockRes;

  beforeEach(() => {
    jest.clearAllMocks();
    mockRes = {
      writeHead: jest.fn(),
      end: jest.fn(),
    };

    // Default mock implementations
    auth.generateIdentityToken.mockReturnValue('mock-identity-token');
    auth.generateSessionToken.mockReturnValue('mock-session-token');
    auth.generateAuthorizationGrant.mockReturnValue('mock-auth-grant');
    auth.generateAccessToken.mockReturnValue('mock-access-token');
    auth.generateToken.mockReturnValue('mock-token');
    auth.parseToken.mockReturnValue(null);
    auth.extractServerAudienceFromHeaders.mockReturnValue(null);
    storage.registerSession.mockResolvedValue();
    storage.registerAuthGrant.mockResolvedValue();
    storage.removeSession.mockResolvedValue(true);
  });

  describe('handleGameSessionNew', () => {
    it('should create new game session', () => {
      const req = {};
      const body = { uuid: 'test-uuid', name: 'TestPlayer' };

      sessionRoutes.handleGameSessionNew(req, mockRes, body, body.uuid, body.name);

      expect(auth.generateIdentityToken).toHaveBeenCalledWith('test-uuid', 'TestPlayer', null);
      expect(auth.generateSessionToken).toHaveBeenCalledWith('test-uuid');
      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
    });

    it('should include session token and identity token in response', () => {
      const req = {};
      const body = {};

      sessionRoutes.handleGameSessionNew(req, mockRes, body, 'uuid', 'name');

      const response = JSON.parse(mockRes.end.mock.calls[0][0]);
      expect(response.sessionToken).toBeDefined();
      expect(response.identityToken).toBeDefined();
      expect(response.expiresIn).toBeDefined();
    });
  });

  describe('handleGameSessionRefresh', () => {
    it('should refresh session', async () => {
      const req = {};
      const body = { sessionToken: 'old-token' };
      const headers = {};

      await sessionRoutes.handleGameSessionRefresh(req, mockRes, body, 'uuid', 'name', headers);

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
    });

    it('should extract info from existing token', async () => {
      auth.extractServerAudienceFromHeaders.mockReturnValue('server-audience');

      const req = {};
      const body = { sessionToken: 'jwt.token.here' };
      const headers = { authorization: 'Bearer jwt.token.here' };

      await sessionRoutes.handleGameSessionRefresh(req, mockRes, body, 'uuid', 'name', headers);

      expect(auth.extractServerAudienceFromHeaders).toHaveBeenCalledWith(headers);
      expect(storage.registerSession).toHaveBeenCalled();
    });
  });

  describe('handleGameSessionChild', () => {
    it('should create child session with identity token', () => {
      const req = {};
      const body = { scopes: ['hytale:server', 'hytale:editor'] };

      sessionRoutes.handleGameSessionChild(req, mockRes, body, 'uuid', 'name');

      expect(auth.generateIdentityToken).toHaveBeenCalledWith('uuid', 'name', ['hytale:server', 'hytale:editor']);
      expect(auth.generateSessionToken).toHaveBeenCalled();
      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
    });

    it('should return identity and session tokens', () => {
      const req = {};
      const body = {};

      sessionRoutes.handleGameSessionChild(req, mockRes, body, 'uuid', 'name');

      const response = JSON.parse(mockRes.end.mock.calls[0][0]);
      expect(response.identityToken).toBeDefined();
      expect(response.sessionToken).toBeDefined();
    });

    it('should pass scopes as array to generateIdentityToken', () => {
      const req = {};
      const body = { scopes: ['hytale:server', 'hytale:editor'] };

      sessionRoutes.handleGameSessionChild(req, mockRes, body, 'uuid', 'name');

      expect(auth.generateIdentityToken).toHaveBeenCalledWith('uuid', 'name', ['hytale:server', 'hytale:editor']);
    });

    it('should pass scopes as string to generateIdentityToken', () => {
      const req = {};
      const body = { scope: 'hytale:server hytale:editor' };

      sessionRoutes.handleGameSessionChild(req, mockRes, body, 'uuid', 'name');

      expect(auth.generateIdentityToken).toHaveBeenCalledWith('uuid', 'name', 'hytale:server hytale:editor');
    });
  });

  describe('handleGameSessionDelete', () => {
    it('should remove session and return 204', async () => {
      const req = {};
      const headers = { authorization: 'Bearer session-token' };

      await sessionRoutes.handleGameSessionDelete(req, mockRes, headers);

      expect(storage.removeSession).toHaveBeenCalled();
      expect(mockRes.writeHead).toHaveBeenCalledWith(204);
    });

    it('should handle missing authorization header', async () => {
      const req = {};
      const headers = {};

      await sessionRoutes.handleGameSessionDelete(req, mockRes, headers);

      expect(mockRes.writeHead).toHaveBeenCalledWith(204);
    });
  });

  describe('handleAuthorizationGrant', () => {
    it('should generate authorization grant', () => {
      const req = {};
      const body = { audience: 'server-123' };
      const headers = {};

      sessionRoutes.handleAuthorizationGrant(req, mockRes, body, 'uuid', 'name', headers);

      expect(auth.generateAuthorizationGrant).toHaveBeenCalled();
      expect(storage.registerAuthGrant).toHaveBeenCalled();
    });

    it('should extract from identity token if present', () => {
      auth.parseToken.mockReturnValue({ uuid: 'token-uuid', name: 'TokenName' });

      const req = {};
      const body = {
        identityToken: 'valid.jwt.token',
        audience: 'server-123',
      };
      const headers = {};

      sessionRoutes.handleAuthorizationGrant(req, mockRes, body, 'uuid', 'name', headers);

      expect(auth.generateAuthorizationGrant).toHaveBeenCalled();
    });
  });

  describe('handleTokenExchange', () => {
    it('should exchange auth grant for access token', () => {
      auth.parseToken.mockReturnValue({
        uuid: 'player-uuid',
        name: 'Player',
        aud: 'server-123',
      });

      const req = {};
      const body = { authorizationGrant: 'valid.auth.grant' };
      const headers = {};

      sessionRoutes.handleTokenExchange(req, mockRes, body, 'uuid', 'name', headers);

      expect(auth.generateAccessToken).toHaveBeenCalled();
      expect(storage.registerSession).toHaveBeenCalled();
    });

    it('should include certificate fingerprint when provided', () => {
      auth.parseToken.mockReturnValue({ uuid: 'uuid', name: 'name', aud: 'aud' });

      const req = {};
      const body = {
        authorizationGrant: 'grant',
        x509Fingerprint: 'fingerprint123',
      };
      const headers = {};

      sessionRoutes.handleTokenExchange(req, mockRes, body, 'uuid', 'name', headers);

      expect(auth.generateAccessToken).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.any(String),
        'fingerprint123',
        null
      );
    });
  });

  describe('handleSession (generic)', () => {
    it('should return session response', () => {
      const req = {};
      const body = {};

      sessionRoutes.handleSession(req, mockRes, body, 'uuid', 'name');

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
    });
  });

  describe('handleAuth (generic)', () => {
    it('should return auth response', () => {
      const req = {};
      const body = {};

      sessionRoutes.handleAuth(req, mockRes, body, 'uuid', 'name');

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
    });
  });

  describe('handleToken (generic)', () => {
    it('should return token response', () => {
      const req = {};
      const body = {};

      sessionRoutes.handleToken(req, mockRes, body, 'uuid', 'name');

      expect(mockRes.writeHead).toHaveBeenCalledWith(200, expect.any(Object));
    });
  });

  describe('handleValidate', () => {
    it('should validate and return success', () => {
      const req = {};
      const body = {};

      sessionRoutes.handleValidate(req, mockRes, body, 'uuid', 'name');

      const response = JSON.parse(mockRes.end.mock.calls[0][0]);
      expect(response.valid).toBe(true);
    });
  });

  describe('handleRefresh', () => {
    it('should refresh and return new tokens', () => {
      const req = {};
      const body = {};

      sessionRoutes.handleRefresh(req, mockRes, body, 'uuid', 'name');

      const response = JSON.parse(mockRes.end.mock.calls[0][0]);
      expect(response.session_token).toBeDefined();
      expect(response.identity_token).toBeDefined();
    });
  });
});
