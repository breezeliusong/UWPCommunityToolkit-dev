// ******************************************************************
// Copyright (c) Microsoft. All rights reserved.
// This code is licensed under the MIT License (MIT).
// THE CODE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE CODE OR THE USE OR OTHER DEALINGS IN THE CODE.
// ******************************************************************

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Microsoft.Toolkit.Uwp.Services.Exceptions;
using Newtonsoft.Json;
using Windows.Security.Authentication.Web;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.Storage.Streams;

namespace Microsoft.Toolkit.Uwp.Services.Twitter
{
    /// <summary>
    /// Data Provider for connecting to Twitter service.
    /// </summary>
    public class TwitterDataProvider : DataProviderBase<TwitterDataConfig, Tweet>
    {
        /// <summary>
        /// Base Url for service.
        /// </summary>
        private const string BaseUrl = "https://api.twitter.com/1.1";
        private const string OAuthBaseUrl = "https://api.twitter.com/oauth";
        private const string PublishUrl = "https://upload.twitter.com/1.1";

        /// <summary>
        /// Base Url for service.
        /// </summary>
        private readonly TwitterOAuthTokens _tokens;

        /// <summary>
        /// Password vault used to store access tokens
        /// 私有只读的密码存储库_vault，只能本应用或服务可访问
        /// Represents a Credential Locker of credentials.
        /// The contents of the locker are specific to the app or service.
        /// Apps and services don't have access to credentials associated with other apps or services.
        /// </summary>
        private readonly PasswordVault _vault;

        /// <summary>
        /// Gets or sets logged in user information.
        /// </summary>
        public string UserScreenName { get; set; }

        /// <summary>
        /// Gets a value indicating whether the provider is already logged in
        /// </summary>
        public bool LoggedIn { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="TwitterDataProvider"/> class.
        /// Constructor.
        /// 实例化TwitterDataProvider类的时候就新建了一个PasswordVault类的实例并赋值给_vault
        /// 同时将参数token传递给_tokens
        /// </summary>
        /// <param name="tokens">OAuth tokens for request.</param>
        public TwitterDataProvider(TwitterOAuthTokens tokens)
        {
            _tokens = tokens;
            _vault = new PasswordVault();
        }

        /// <summary>
        /// Retrieve user data.
        /// </summary>
        /// <param name="screenName">User screen name or null for current logged user</param>
        /// <returns>Returns user data.</returns>
        public async Task<TwitterUser> GetUserAsync(string screenName = null)
        {
            string rawResult = null;
            try
            {
                var userScreenName = screenName ?? UserScreenName;
                var uri = new Uri($"{BaseUrl}/users/show.json?screen_name={userScreenName}");

                TwitterOAuthRequest request = new TwitterOAuthRequest();
                rawResult = await request.ExecuteGetAsync(uri, _tokens);
                return JsonConvert.DeserializeObject<TwitterUser>(rawResult);
            }
            catch (WebException wex)
            {
                HttpWebResponse response = wex.Response as HttpWebResponse;
                if (response != null)
                {
                    if (response.StatusCode == HttpStatusCode.NotFound)
                    {
                        throw new UserNotFoundException(screenName);
                    }

                    if ((int)response.StatusCode == 429)
                    {
                        throw new TooManyRequestsException();
                    }

                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        throw new OAuthKeysRevokedException();
                    }
                }

                throw;
            }
            catch
            {
                if (!string.IsNullOrEmpty(rawResult))
                {
                    var errors = JsonConvert.DeserializeObject<TwitterErrors>(rawResult);

                    throw new TwitterException { Errors = errors };
                }

                throw;
            }
        }

        /// <summary>
        /// Retrieve user timeline data with specific parser.
        /// </summary>
        /// <typeparam name="TSchema">Strong type for results.</typeparam>
        /// <param name="screenName">User screen name.</param>
        /// <param name="maxRecords">Upper record limit.</param>
        /// <param name="parser">Specific results parser.</param>
        /// <returns>Returns strongly typed list of results.</returns>
        public async Task<IEnumerable<TSchema>> GetUserTimeLineAsync<TSchema>(string screenName, int maxRecords, IParser<TSchema> parser)
            where TSchema : SchemaBase
        {
            string rawResult = null;
            try
            {
                var uri = new Uri($"{BaseUrl}/statuses/user_timeline.json?screen_name={screenName}&count={maxRecords}&include_rts=1");

                TwitterOAuthRequest request = new TwitterOAuthRequest();
                rawResult = await request.ExecuteGetAsync(uri, _tokens);

                var result = parser.Parse(rawResult);
                return result
                        .Take(maxRecords)
                        .ToList();
            }
            catch (WebException wex)
            {
                HttpWebResponse response = wex.Response as HttpWebResponse;
                if (response != null)
                {
                    if (response.StatusCode == HttpStatusCode.NotFound)
                    {
                        throw new UserNotFoundException(screenName);
                    }

                    if ((int)response.StatusCode == 429)
                    {
                        throw new TooManyRequestsException();
                    }

                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        throw new OAuthKeysRevokedException();
                    }
                }

                throw;
            }
            catch
            {
                if (!string.IsNullOrEmpty(rawResult))
                {
                    var errors = JsonConvert.DeserializeObject<TwitterErrors>(rawResult);

                    throw new TwitterException { Errors = errors };
                }

                throw;
            }
        }

        /// <summary>
        /// Search for specific hash tag with specific parser.
        /// </summary>
        /// <typeparam name="TSchema">Strong type for results.</typeparam>
        /// <param name="hashTag">Hash tag.</param>
        /// <param name="maxRecords">Upper record limit.</param>
        /// <param name="parser">Specific results parser.</param>
        /// <returns>Returns strongly typed list of results.</returns>
        public async Task<IEnumerable<TSchema>> SearchAsync<TSchema>(string hashTag, int maxRecords, IParser<TSchema> parser)
            where TSchema : SchemaBase
        {
            try
            {
                var uri = new Uri($"{BaseUrl}/search/tweets.json?q={Uri.EscapeDataString(hashTag)}&count={maxRecords}");
                TwitterOAuthRequest request = new TwitterOAuthRequest();
                var rawResult = await request.ExecuteGetAsync(uri, _tokens);

                var result = parser.Parse(rawResult);
                return result
                        .Take(maxRecords)
                        .ToList();
            }
            catch (WebException wex)
            {
                HttpWebResponse response = wex.Response as HttpWebResponse;
                if (response != null)
                {
                    if ((int)response.StatusCode == 429)
                    {
                        throw new TooManyRequestsException();
                    }

                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        throw new OAuthKeysRevokedException();
                    }
                }

                throw;
            }
        }

        // 密码凭证，用于保存密码（如果有，从本地设置中获取，否则返回null）
        private PasswordCredential PasswordCredential
        {
            get
            {
                // Password vault remains when app is uninstalled so checking the local settings value
                // 检查本地有没有账户存储设置
                if (ApplicationData.Current.LocalSettings.Values["TwitterScreenName"] == null)
                {
                    return null;
                }

                // 获取存储库中的所有密码凭证
                var passwordCredentials = _vault.RetrieveAll();

                // 根据条件查找对应的PasswordCredential
                var temp = passwordCredentials.FirstOrDefault(c => c.Resource == "TwitterAccessToken");

                if (temp == null)
                {
                    return null;
                }

                return _vault.Retrieve(temp.Resource, temp.UserName);
            }
        }

        /// <summary>
        /// Log user in to Twitter.
        /// 是否登陆状态
        /// </summary>
        /// <returns>Boolean indicating login success.</returns>
        public async Task<bool> LoginAsync()
        {
            var twitterCredentials = PasswordCredential;

            // 判断密码证书!=null读取本地存储
            //if (twitterCredentials != null)
            //{
            //    _tokens.AccessToken = twitterCredentials.UserName;
            //    _tokens.AccessTokenSecret = twitterCredentials.Password;
            //    UserScreenName = ApplicationData.Current.LocalSettings.Values["TwitterScreenName"].ToString();
            //    LoggedIn = true;
            //    return true;
            //}

            // （第一次网络请求封装在此）在这里判断结果，确认CallbackUri与设置的CallbackUri一致
            if (await InitializeRequestAccessTokensAsync(_tokens.CallbackUri) == false)
            {
                LoggedIn = false;
                return false;
            }

            string requestToken = _tokens.RequestToken;
            string twitterUrl = $"{OAuthBaseUrl}/authorize?oauth_token={requestToken}";

            Uri startUri = new Uri(twitterUrl);
            Uri endUri = new Uri(_tokens.CallbackUri);

            // UWP封装好的验证请求，第二次网络请求，获取的oauth_token是被认证之后的
            var result = await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None, startUri, endUri);

            switch (result.ResponseStatus)
            {
                case WebAuthenticationStatus.Success:
                    LoggedIn = true;
                    Debug.WriteLine(result.ResponseData);
                    return await ExchangeRequestTokenForAccessTokenAsync(result.ResponseData);
                case WebAuthenticationStatus.ErrorHttp:
                    Debug.WriteLine("WAB failed, message={0}", result.ResponseErrorDetail.ToString());
                    LoggedIn = false;
                    return false;
                case WebAuthenticationStatus.UserCancel:
                    Debug.WriteLine("WAB user aborted.");
                    LoggedIn = false;
                    return false;
            }

            LoggedIn = false;
            return false;
        }

        /// <summary>
        /// Log user out of Twitter.
        /// </summary>
        public void Logout()
        {
            var twitterCredentials = PasswordCredential;
            if (twitterCredentials != null)
            {
                _vault.Remove(twitterCredentials);
                ApplicationData.Current.LocalSettings.Values["TwitterScreenName"] = null;
                UserScreenName = null;
            }

            LoggedIn = false;
        }

        /// <summary>
        /// Tweets a status update.
        /// </summary>
        /// <param name="tweet">Tweet text.</param>
        /// <param name="pictures">Pictures to attach to the tweet (up to 4).</param>
        /// <returns>Success or failure.</returns>
        public async Task<bool> TweetStatusAsync(string tweet, params IRandomAccessStream[] pictures)
        {
            try
            {
                var mediaIds = string.Empty;

                if (pictures != null && pictures.Length > 0)
                {
                    var ids = new List<string>();
                    foreach (var picture in pictures)
                    {
                        ids.Add(await UploadPictureAsync(picture));
                    }

                    mediaIds = "&media_ids=" + string.Join(",", ids);
                }

                var uri = new Uri($"{BaseUrl}/statuses/update.json?status={Uri.EscapeDataString(tweet)}{mediaIds}");

                TwitterOAuthRequest request = new TwitterOAuthRequest();
                await request.ExecutePostAsync(uri, _tokens);

                return true;
            }
            catch (WebException wex)
            {
                HttpWebResponse response = wex.Response as HttpWebResponse;
                if (response != null)
                {
                    if ((int)response.StatusCode == 429)
                    {
                        throw new TooManyRequestsException();
                    }

                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        throw new OAuthKeysRevokedException();
                    }
                }

                throw;
            }
        }

        /// <summary>
        /// Publish a picture to Twitter user's medias.
        /// </summary>
        /// <param name="stream">Picture stream.</param>
        /// <returns>Media ID</returns>
        public async Task<string> UploadPictureAsync(IRandomAccessStream stream)
        {
            var uri = new Uri($"{PublishUrl}/media/upload.json");

            // Get picture data
            var fileBytes = new byte[stream.Size];

            await stream.ReadAsync(fileBytes.AsBuffer(), (uint)stream.Size, InputStreamOptions.None);

            stream.Seek(0);

            string boundary = DateTime.Now.Ticks.ToString("x");

            TwitterOAuthRequest request = new TwitterOAuthRequest();
            return await request.ExecutePostMultipartAsync(uri, _tokens, boundary, fileBytes);
        }

        /// <summary>
        /// Returns parser implementation for specified configuration.
        /// </summary>
        /// <param name="config">Query configuration.</param>
        /// <returns>Strongly typed parser.</returns>
        protected override IParser<Tweet> GetDefaultParser(TwitterDataConfig config)
        {
            if (config == null)
            {
                throw new ConfigNullException();
            }

            switch (config.QueryType)
            {
                case TwitterQueryType.Search:
                    return new TwitterSearchParser();
                case TwitterQueryType.Home:
                case TwitterQueryType.User:
                default:
                    return new TweetParser();
            }
        }

        /// <summary>
        /// Wrapper around REST API for making data request.
        /// </summary>
        /// <typeparam name="TSchema">Schema to use</typeparam>
        /// <param name="config">Query configuration.</param>
        /// <param name="maxRecords">Upper limit for records returned.</param>
        /// <param name="parser">IParser implementation for interpreting results.</param>
        /// <returns>Strongly typed list of results.</returns>
        protected override async Task<IEnumerable<TSchema>> GetDataAsync<TSchema>(TwitterDataConfig config, int maxRecords, IParser<TSchema> parser)
        {
            IEnumerable<TSchema> items;
            switch (config.QueryType)
            {
                case TwitterQueryType.User:
                    items = await GetUserTimeLineAsync(config.Query, maxRecords, parser);
                    break;
                case TwitterQueryType.Search:
                    items = await SearchAsync(config.Query, maxRecords, parser);
                    break;
                case TwitterQueryType.Home:
                default:
                    items = await GetHomeTimeLineAsync(maxRecords, parser);
                    break;
            }

            return items;
        }

        /// <summary>
        /// Check validity of configuration.
        /// </summary>
        /// <param name="config">Query configuration.</param>
        protected override void ValidateConfig(TwitterDataConfig config)
        {
            if (config?.Query == null && config?.QueryType != TwitterQueryType.Home)
            {
                throw new ConfigParameterNullException(nameof(config.Query));
            }

            if (_tokens == null)
            {
                throw new ConfigParameterNullException(nameof(_tokens));
            }

            if (string.IsNullOrEmpty(_tokens.ConsumerKey))
            {
                throw new OAuthKeysNotPresentException(nameof(_tokens.ConsumerKey));
            }

            if (string.IsNullOrEmpty(_tokens.ConsumerSecret))
            {
                throw new OAuthKeysNotPresentException(nameof(_tokens.ConsumerSecret));
            }
        }

        /// <summary>
        /// Extract requested token from the REST API response string.
        /// </summary>
        /// <param name="getResponse">REST API response string.</param>
        /// <param name="tokenType">Token type to retrieve.</param>
        /// <returns>Required token.</returns>
        private static string ExtractTokenFromResponse(string getResponse, TwitterOAuthTokenType tokenType)
        {
            string requestOrAccessToken = null;
            string requestOrAccessTokenSecret = null;
            string oauthVerifier = null;
            string oauthCallbackConfirmed = null;
            string screenName = null;
            string[] keyValPairs = getResponse.Split('&');

            for (int i = 0; i < keyValPairs.Length; i++)
            {
                string[] splits = keyValPairs[i].Split('=');
                switch (splits[0])
                {
                    case "screen_name":
                        screenName = splits[1];
                        break;
                    case "oauth_token":
                        requestOrAccessToken = splits[1];
                        break;
                    case "oauth_token_secret":
                        requestOrAccessTokenSecret = splits[1];
                        break;
                    case "oauth_callback_confirmed":
                        oauthCallbackConfirmed = splits[1];
                        break;
                    case "oauth_verifier":
                        oauthVerifier = splits[1];
                        break;
                }
            }

            switch (tokenType)
            {
                case TwitterOAuthTokenType.OAuthRequestOrAccessToken:
                    return requestOrAccessToken;
                case TwitterOAuthTokenType.OAuthRequestOrAccessTokenSecret:
                    return requestOrAccessTokenSecret;
                case TwitterOAuthTokenType.OAuthVerifier:
                    return oauthVerifier;
                case TwitterOAuthTokenType.ScreenName:
                    return screenName;
                case TwitterOAuthTokenType.OAuthCallbackConfirmed:
                    return oauthCallbackConfirmed;
            }

            return string.Empty;
        }

        /// <summary>
        /// Get home time line data.
        /// </summary>
        /// <typeparam name="TSchema">Strong typed result.</typeparam>
        /// <param name="maxRecords">Upper record limit.</param>
        /// <param name="parser">Specific result parser.</param>
        /// <returns>Return strong typed list of results.</returns>
        private async Task<IEnumerable<TSchema>> GetHomeTimeLineAsync<TSchema>(int maxRecords, IParser<TSchema> parser)
            where TSchema : SchemaBase
        {
            try
            {
                var uri = new Uri($"{BaseUrl}/statuses/home_timeline.json?count={maxRecords}");

                TwitterOAuthRequest request = new TwitterOAuthRequest();
                var rawResult = await request.ExecuteGetAsync(uri, _tokens);

                return parser.Parse(rawResult);
            }
            catch (WebException wex)
            {
                HttpWebResponse response = wex.Response as HttpWebResponse;
                if (response != null)
                {
                    if ((int)response.StatusCode == 429)
                    {
                        throw new TooManyRequestsException();
                    }

                    if (response.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        throw new OAuthKeysRevokedException();
                    }
                }

                throw;
            }
        }

        /// <summary>
        /// Package up token request.封装的token请求。
        /// 第一次网络请求，第一次获取oauth_token是未被认证的Request_token。
        /// 按照Twitter Api接入要求，实际是按照OAuth1.0A的步骤进行配置请求参数，获取OAuth_token.
        /// 就是确认设置的输入的CallbackUrl是否与应用设置的CallbackUrl一致，一致则可以获取第一个OAuth_token即OAuth1中的Request_token
        /// </summary>
        /// <param name="twitterCallbackUrl">Callback Uri.</param>
        /// <returns>Success or failure.</returns>
        private async Task<bool> InitializeRequestAccessTokensAsync(string twitterCallbackUrl)
        {
            // 设置url
            var twitterUrl = $"{OAuthBaseUrl}/request_token";

            // 设置参数
            string nonce = GetNonce();
            string timeStamp = GetTimeStamp();
            string sigBaseStringParams = GetSignatureBaseStringParams(_tokens.ConsumerKey, nonce, timeStamp, "oauth_callback=" + Uri.EscapeDataString(twitterCallbackUrl));

            // Uri.EscapeDataString(twitterUrl) Converts a string to its escaped representation.
            string sigBaseString = "GET&" + Uri.EscapeDataString(twitterUrl) + "&" + Uri.EscapeDataString(sigBaseStringParams);

            // 第一次签名，调用该方法获取签名
            string signature = GetSignature(sigBaseString, _tokens.ConsumerSecret);

            twitterUrl += "?" + sigBaseStringParams + "&oauth_signature=" + Uri.EscapeDataString(signature);

            string getResponse;

            // 可以从getResponse中获取OAuth_token
            using (var request = new HttpHelperRequest(new Uri(twitterUrl), Windows.Web.Http.HttpMethod.Get))
            {
                using (var response = await HttpHelper.Instance.SendRequestAsync(request).ConfigureAwait(false))
                {
                    var data = await response.GetTextResultAsync().ConfigureAwait(false);
                    if (response.Success)
                    {
                        getResponse = data;
                    }
                    else
                    {
                        Debug.WriteLine("HttpHelper call failed trying to retrieve Twitter Request Tokens.  Message: {0}", data);
                        return false;
                    }
                }
            }

            // 获取callbackConfirmed确认的结果
            var callbackConfirmed = ExtractTokenFromResponse(getResponse, TwitterOAuthTokenType.OAuthCallbackConfirmed);
            if (Convert.ToBoolean(callbackConfirmed) != true)
            {
                return false;
            }

            // 截取返回结果中的对应数据，并将获取的数据保存到_tokens实例中
            _tokens.RequestToken = ExtractTokenFromResponse(getResponse, TwitterOAuthTokenType.OAuthRequestOrAccessToken);
            _tokens.RequestTokenSecret = ExtractTokenFromResponse(getResponse, TwitterOAuthTokenType.OAuthRequestOrAccessTokenSecret);

            return true;
        }

        /// <summary>
        /// Build signature base string.
        /// 建立基本字符串签名，参数按字母表顺序排列
        /// </summary>
        /// <param name="consumerKey">Consumer Key.</param>
        /// <param name="nonce">Nonce.</param>
        /// <param name="timeStamp">Timestamp.</param>
        /// <param name="additionalParameters">Any additional parameter name/values that need appending to base string.</param>
        /// <returns>Signature base string.</returns>
        private string GetSignatureBaseStringParams(string consumerKey, string nonce, string timeStamp, string additionalParameters = "")
        {
            string sigBaseStringParams = additionalParameters;
            sigBaseStringParams += "&" + "oauth_consumer_key=" + consumerKey;
            sigBaseStringParams += "&" + "oauth_nonce=" + nonce;
            sigBaseStringParams += "&" + "oauth_signature_method=HMAC-SHA1";
            sigBaseStringParams += "&" + "oauth_timestamp=" + timeStamp;
            sigBaseStringParams += "&" + "oauth_version=1.0";

            return sigBaseStringParams;
        }

        // 第二次签名，参数不按字母表顺序排列
        private string GetSignatureBaseStringParams2(string consumerKey, string nonce, string timeStamp, string additionalParameters = "")
        {
            string sigBaseStringParams = additionalParameters;
            sigBaseStringParams += "&" + "oauth_nonce=" + nonce;
            sigBaseStringParams += "&" + "oauth_timestamp=" + timeStamp;
            sigBaseStringParams += "&" + "oauth_consumer_key=" + consumerKey;
            sigBaseStringParams += "&" + "oauth_signature_method=HMAC-SHA1";
            sigBaseStringParams += "&" + "oauth_version=1.0";

            return sigBaseStringParams;
        }

        /// <summary>
        /// Extract and initialize access tokens.
        /// 第三次网络请求，获取oauth_token即最终的access_tokens，并保存于本地
        /// </summary>
        /// <param name="webAuthResultResponseData">WAB data containing appropriate tokens.</param>
        /// <returns>Success or failure.</returns>
        private async Task<bool> ExchangeRequestTokenForAccessTokenAsync(string webAuthResultResponseData)
        {
            string responseData = webAuthResultResponseData.Substring(webAuthResultResponseData.IndexOf("oauth_token"));
            string requestToken = ExtractTokenFromResponse(responseData, TwitterOAuthTokenType.OAuthRequestOrAccessToken);

            // Ensure requestToken matches accessToken per Twitter documentation.
            if (requestToken != _tokens.RequestToken)
            {
                return false;
            }

            string oAuthVerifier = ExtractTokenFromResponse(responseData, TwitterOAuthTokenType.OAuthVerifier);

            string twitterUrl = $"{OAuthBaseUrl}/access_token";

            string timeStamp = GetTimeStamp();
            string nonce = GetNonce();

            string sigBaseStringParams = GetSignatureBaseStringParams2(_tokens.ConsumerKey, nonce, timeStamp, "oauth_token=" + requestToken);

            string sigBaseString = "POST&";
            sigBaseString += Uri.EscapeDataString(twitterUrl) + "&" + Uri.EscapeDataString(sigBaseStringParams);

            // 第二次签名
            string signature = GetSignature(sigBaseString, _tokens.ConsumerSecret);
            string data = null;

            string authorizationHeaderParams = "oauth_consumer_key=\"" + _tokens.ConsumerKey + "\", oauth_nonce=\"" + nonce + "\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"" + Uri.EscapeDataString(signature) + "\", oauth_timestamp=\"" + timeStamp + "\", oauth_token=\"" + Uri.EscapeDataString(requestToken) + "\", oauth_verifier=\"" + Uri.EscapeUriString(oAuthVerifier) + "\" , oauth_version=\"1.0\"";

            using (var request = new HttpHelperRequest(new Uri(twitterUrl), Windows.Web.Http.HttpMethod.Post))
            {
                request.Headers.Authorization = new Windows.Web.Http.Headers.HttpCredentialsHeaderValue("OAuth", authorizationHeaderParams);

                using (var response = await HttpHelper.Instance.SendRequestAsync(request).ConfigureAwait(false))
                {
                    data = await response.GetTextResultAsync().ConfigureAwait(false);
                }
            }

            var screenName = ExtractTokenFromResponse(data, TwitterOAuthTokenType.ScreenName);
            var accessToken = ExtractTokenFromResponse(data, TwitterOAuthTokenType.OAuthRequestOrAccessToken);
            var accessTokenSecret = ExtractTokenFromResponse(data, TwitterOAuthTokenType.OAuthRequestOrAccessTokenSecret);

            UserScreenName = screenName;
            _tokens.AccessToken = accessToken;
            _tokens.AccessTokenSecret = accessTokenSecret;

            var passwordCredential = new PasswordCredential("TwitterAccessToken", accessToken, accessTokenSecret);
            ApplicationData.Current.LocalSettings.Values["TwitterScreenName"] = screenName;
            _vault.Add(passwordCredential);

            return true;
        }

        /// <summary>
        /// Generate nonce.
        /// 产生独一无二随机数，Twitter用此值确定是否多次请求
        /// </summary>
        /// <returns>Nonce.</returns>
        private string GetNonce()
        {
            Random rand = new Random();
            int nonce = rand.Next(1000000000);
            return nonce.ToString();
        }

        /// <summary>
        /// Generate timestamp.
        /// 指定什么时候创建的请求
        /// This value should be the number of seconds since the Unix epoch at the point the request is generated
        /// </summary>
        /// <returns>Timestamp.</returns>
        private string GetTimeStamp()
        {
            TimeSpan sinceEpoch = DateTime.UtcNow - new DateTime(1970, 1, 1);
            return Math.Round(sinceEpoch.TotalSeconds).ToString();
        }

        /// <summary>
        /// Generate request signature.
        /// 产生请求签名，使用HMAC_SHA1加密算法
        /// </summary>
        /// <param name="sigBaseString">Base string.</param>
        /// <param name="consumerSecretKey">Consumer secret key.</param> 
        /// <returns>Signature.</returns>
        private string GetSignature(string sigBaseString, string consumerSecretKey)
        {
            IBuffer keyMaterial = CryptographicBuffer.ConvertStringToBinary(consumerSecretKey + "&", BinaryStringEncoding.Utf8);
            MacAlgorithmProvider hmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
            CryptographicKey macKey = hmacSha1Provider.CreateKey(keyMaterial);
            IBuffer dataToBeSigned = CryptographicBuffer.ConvertStringToBinary(sigBaseString, BinaryStringEncoding.Utf8);
            IBuffer signatureBuffer = CryptographicEngine.Sign(macKey, dataToBeSigned);
            string signature = CryptographicBuffer.EncodeToBase64String(signatureBuffer);

            return signature;
        }
    }
}
