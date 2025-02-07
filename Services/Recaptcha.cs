
using System.Text.Json.Nodes;
using System.Net;

namespace AS_Assignment_2.Services
{
    public class RecaptchaService
    {
        private readonly string _secretKey;
        private readonly string _verificationUrl;
        private readonly HttpClient _httpClient;

        public RecaptchaService(HttpClient httpClient, IConfiguration configuration)
        {
            _secretKey = configuration["GoogleRecaptchaConfig:SecretKey"];
            _verificationUrl = configuration["GoogleRecaptchaConfig:VerficationUrl"];
            _httpClient = httpClient;
        }

        public async Task<bool> VerifyReCaptchaV3(string response)
        {
            var sanitizedResponse = WebUtility.HtmlEncode(response);
            var content = new MultipartFormDataContent();
            content.Add(new StringContent(sanitizedResponse), "response");
            content.Add(new StringContent(_secretKey), "secret");

            var result = await _httpClient.PostAsync(_verificationUrl, content);

            if (result.IsSuccessStatusCode)
            {
                var strResponse = await result.Content.ReadAsStringAsync();

                var jsonResponse = JsonNode.Parse(strResponse);
                if (jsonResponse != null)
                {
                    var success = ((bool?)jsonResponse["success"]);
                    if (success != null && success == true) return true;
                }
            }

            return false;
        }
    }
}
