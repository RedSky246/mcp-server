package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.serialization.json.*

class Scanner(val api: MontoyaApi) {
    val BURP_REST_API_HOST = "127.0.0.1"
    val BURP_REST_API_PORT = 1337
    val BURP_REST_API_KEY = System.getenv("BURP_REST_API_KEY")
    val BURP_REST_API_PATH = if (BURP_REST_API_KEY != null) "/$BURP_REST_API_KEY" else ""

    val SCAN_ID_HEADER_FIELD = "location"
    val SCAN_STATUS_JSON_FIELD = "scan_status"
    val SLEEP_MILLISECONDS: Long = 1000

    fun createScan(url: String, namedConfigurations: List<String>): String {
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

        var scanConfiguration = ""
        namedConfigurations.forEachIndexed { index, namedConfiguration ->
            run {
                scanConfiguration += "{\"name\": \"$namedConfiguration\", \"type\": \"NamedConfiguration\"}"
                if ((index + 1) < namedConfigurations.size) {
                    scanConfiguration += ", "
                }
            }
        }
        scanConfiguration = "[$scanConfiguration]"

        request = request.withBody(
            "\r\n" +
                    "{\r\n" +
                    "  \"scan_configurations\": $scanConfiguration,\r\n" +
                    "  \"urls\": [\"$url\"]\r\n" +
                    "}\r\n" +
                    "\r\n"
        )

        val response = api.http().sendRequest(request)
        return response.response().header(SCAN_ID_HEADER_FIELD).value()
    }

    // This function was generated with ChatGPT.
    fun extractAllRequestResponse(element: JsonElement): List<JsonElement> {
        val result = mutableListOf<JsonElement>()

        when (element) {
            is JsonObject -> {
                for ((key, value) in element) {
                    if (key == "request_response") {
                        result.add(value)
                    }
                    result.addAll(extractAllRequestResponse(value))
                }
            }

            is JsonArray -> {
                for (item in element) {
                    result.addAll(extractAllRequestResponse(item))
                }
            }

            else -> {}
        }

        return result
    }

    fun getScanResult(id: String): String {
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
                val issues = body.jsonObject["issue_events"]
                val resultObjects = mutableListOf<JsonObject>()
                if (issues is JsonArray) {
                    for (issue in issues) {
                        val issueObject = issue.jsonObject["issue"]
                        if (issueObject != null &&
                            (issueObject.jsonObject["severity"]!!.toString().equals("\"medium\"") ||
                                    issueObject.jsonObject["severity"]!!.toString().equals("\"high\""))
                        ) {
                            val evidences = issueObject.jsonObject["evidence"]

                            val completeRequests = mutableListOf<String>()
                            val requestResponses = extractAllRequestResponse(evidences!!)
                            for (requestResponse in requestResponses) {
                                val requests = requestResponse.jsonObject["request"]
                                if (requests is JsonArray) {
                                    var completeRequest = ""
                                    for (request in requests) {
                                        var data = request.jsonObject["data"].toString()
                                        try {
                                            data = data.substring(1, data.length - 1)
                                            data = api.utilities().base64Utils().decode(data).toString()
                                            completeRequest += data
                                        } catch (e: Exception) {
                                            api.logging()
                                                .logToOutput("Could not decode request, data: $data - error: ${e.message}")
                                        }
                                    }
                                    completeRequests.add(completeRequest)
                                }
                            }

                            val resultObject = buildJsonObject {
                                put("name", issueObject.jsonObject["name"]!!)
                                put("severity", issueObject.jsonObject["severity"]!!)
                                put("confidence", issueObject.jsonObject["confidence"]!!)
                                put("issue_background", issueObject.jsonObject["issue_background"]!!)
                                put("description", issueObject.jsonObject["description"]!!)
                                put("remediation", issueObject.jsonObject["remediation"]!!)
                                put("evidence", completeRequests.toString())
                            }
                            resultObjects.add(resultObject)
                        }
                    }
                }
                val result = buildJsonArray {
                    addJsonArray {
                        for (result in resultObjects) add(result)
                    }
                }

                return result.toString()
            }

            Thread.sleep(SLEEP_MILLISECONDS)
        }
    }
}