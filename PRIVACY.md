# Privacy Policy

## Feishu Approval Trigger Plugin

**Last Updated**: January 6, 2025

### Data Collection

This plugin processes the following data when receiving Feishu approval webhook events:

1. **Feishu Credentials** (stored in Dify subscription):
   - App ID
   - App Secret
   - Verification Token
   - Encrypt Key (optional)

2. **Event Data** (received from Feishu webhooks):
   - Approval instance code
   - Approval definition code
   - Approval status
   - Operation timestamp
   - User IDs and tenant information

### Data Usage

- **Credentials**: Used exclusively for authenticating webhook requests from Feishu
- **Event Data**: Passed through to Dify workflows as variables for business logic processing
- **No Data Storage**: This plugin does not store any data persistently. All data is processed in memory and passed to Dify workflows

### Data Transmission

- **Incoming**: Receives encrypted or plaintext webhook events from Feishu servers
- **Outgoing**: Passes event data to Dify workflow engine
- **No Third-Party Sharing**: Data is not shared with any third parties

### Security Measures

1. **Signature Verification**: When Encrypt Key is configured, all requests are verified using SHA256 HMAC signatures
2. **Payload Encryption**: Supports AES-256-CBC encryption for sensitive data
3. **Token Validation**: Verifies Verification Token to ensure requests originate from authorized Feishu applications
4. **No Logging**: Sensitive data (credentials, approval content) is not logged

### User Rights

Users can:
- Delete credentials by removing the subscription in Dify
- Stop receiving events by disabling the event subscription in Feishu Developer Console
- Rotate credentials at any time in Feishu console and update them in Dify

### Compliance

This plugin:
- Does not collect personal data beyond what's necessary for webhook processing
- Does not retain data after processing
- Processes data in accordance with Feishu's event subscription policies

### Contact

For privacy concerns or questions, please contact the plugin maintainer or file an issue in the plugin repository.
