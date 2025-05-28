## Connector capabilities

1. What resources does the connector sync?
- Tenable connector syncs Users, Groups, Roles and Permisssions.

2. Can the connector provision any resources? If so, which ones?
- The connector can provision entitlements for Users to Groups and Roles.
- This connector can also provision Accounts.

## Connector credentials

1. What credentials or information are needed to set up the connector? (For example, API key, client ID and secret, domain, etc.)
- For this connector, we require an api key (split into access-key and secret-key when generated). While generating the keys, Tenable creates an access key and a secret key. The matching flags are 'access-key' and 'secret-key', both are required.
Please keep in mind that Teneable VM can restrict access by IP, if configured, remember to add the proper configurations for c1.

2. For each item in the list above:

   * How does a user create or look up that credential or info? Please include links to (non-gated) documentation, screenshots (of the UI or of gated docs), or a video of the process.
    - For API KEYS go to My Profile in the Tenable Platform, select API KEYS in the left menu. Click Generate (WARNING: generating api keys renders any previously generated key obsolete).
    

   * Does the credential need any specific scopes or permissions? If so, list them here.
    - The user should be an admin.

   * If applicable: Is the list of scopes or permissions different to sync (read) versus provision (read-write)? If so, list the difference here.
   - This doesn't apply. An Access Token with the same scope as the admin user is enough for syncing and provisioning.

   * What level of access or permissions does the user need in order to create the credentials? (For example, must be a super administrator, must have access to the admin console, etc.)
   - It should be an Administrator (64). For more information visit: [Role Documentation](https://developer.tenable.com/docs/roles)