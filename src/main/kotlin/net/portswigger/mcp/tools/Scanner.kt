package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

class Scanner(val api: MontoyaApi) {
    val BURP_REST_API_HOST = "127.0.0.1"
    val BURP_REST_API_PORT = 1337
    val BURP_REST_API_KEY = System.getenv("BURP_REST_API_KEY")
    val BURP_REST_API_PATH = if (BURP_REST_API_KEY != null) "/$BURP_REST_API_KEY" else ""

    val SCAN_ID_HEADER_FIELD = "location"
    val SCAN_STATUS_JSON_FIELD = "scan_status"
    val SLEEP_MILLISECONDS: Long = 1000

    fun createActiveScan(url: String): String {
        var request = HttpRequest.httpRequest(
            HttpService.httpService(BURP_REST_API_HOST, BURP_REST_API_PORT, false),
            "\r\n" +
                    "POST $BURP_REST_API_PATH/v0.1/scan HTTP/1.1\r\n" +
                    "Host: $BURP_REST_API_HOST:$BURP_REST_API_PORT\r\n" +
                    "Content-Type: application/json\r\n" +
                    "\r\n" +
                    "{\r\n" +
                    "  \r\n" +
                    "}\r\n" +
                    "\r\n"
        )
        request = request.withBody(
            "\r\n" +
                    "{\r\n" +
                    "  \"urls\": [\"$url\"]\r\n" +
                    "}\r\n" +
                    "\r\n"
        )

        val response = api.http().sendRequest(request)
        return response.response().header(SCAN_ID_HEADER_FIELD).value()
    }

    fun getActiveScanResult(id: String): String {
        while (true) {
            val request = HttpRequest.httpRequest(
                HttpService.httpService(BURP_REST_API_HOST, BURP_REST_API_PORT, false),
                "\r\n" +
                        "GET $BURP_REST_API_PATH/v0.1/scan/$id HTTP/1.1\r\n" +
                        "Host: $BURP_REST_API_HOST:$BURP_REST_API_PORT\r\n" +
                        "\r\n"
            )

            val response = api.http().sendRequest(request)
            val body = Json.parseToJsonElement(response.response().bodyToString())
            val state = body.jsonObject[SCAN_STATUS_JSON_FIELD].toString()

            if (!state.equals("\"initializing\"") &&
                !state.equals("\"crawling\"") &&
                !state.equals("\"paused\"") &&
                !state.equals("\"auditing\"")
            ) {
                return body.toString()
            }

            Thread.sleep(SLEEP_MILLISECONDS)
        }
    }
}