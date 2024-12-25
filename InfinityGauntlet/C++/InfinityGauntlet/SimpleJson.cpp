#include "SimpleJson.hpp"
#include "SecureString.hpp"
#include "StringCrypt.hpp"
#include "ThreadPool.hpp"
#include <iostream>

SimpleJson::SimpleJson() : jsonString(std::make_unique<SecureString>()) {}

SimpleJson::~SimpleJson() = default;

void SimpleJson::addString(const char* key, const SecureString& value) {
    SecureString keyStr(key);
    appendKeyValue(keyStr, value, true); // This is a string value.
}

void SimpleJson::addInt64(const char* key, int64_t value) {
    SecureString keyStr(key);
    SecureString valueStr(std::to_string(value).c_str());
    appendKeyValue(keyStr, valueStr, false); // This is not a string value.
}

void SimpleJson::addBool(const char* key, bool value) {
    SecureString keyStr(key);
    SecureString valueStr = value ? "true" : "false";
    appendKeyValue(keyStr, valueStr, false); // This is not a string value.
}

SecureString SimpleJson::dump() {
    SecureString result("{");

    for (const auto& kv : keyValuePairs) {
        if (result[result.size() - 1] != '{') {
            result.append(",");
        }

        // For vector type, the key is already included in the value.
        if (kv.second.isVector) {
            result.append("\"");
            result.append(kv.first->c_str());
        }
        else {
            result.append("\"");
            result.append(kv.first->c_str());
            result.append("\":");

            if (kv.second.isString) {
                result.append("\"");
                result.append(kv.second.value->c_str());
                result.append("\"");
            }
            else {
                result.append(kv.second.value->c_str());
            }
        }
    }

    result.append("}");
    return result;
}

void SimpleJson::addStringVector(const char* key, const std::vector<std::unique_ptr<SecureString>>& values) {
    SecureString keyStr(key);
    keyStr.append("\":[");

    if (!values.empty()) {
        bool first = true;

        for (const auto& value : values) {
            if (!first) {
                keyStr.append(",");
            }
            keyStr.append("\"");
            if (value) {
                keyStr.append(value->c_str());
            }
            keyStr.append("\"");
            first = false;
        }
    }

    keyStr.append("]");

    // Insert key and an empty value into keyValuePairs  
    auto newKey = std::make_unique<SecureString>(keyStr);
    keyValuePairs[std::move(newKey)] = JsonValue(true);  // Marking as a vector
}


int64_t SimpleJson::extractID(const SecureString& jsonString) {
    SecureString searchPattern(StringCrypt::DecryptString(StringCrypt::IDJSONPATTERN_CRYPT).c_str());
    const char* jsonStringCStr = jsonString.c_str(); // Assuming SecureString has c_str()

    const char* idPosition = std::strstr(jsonStringCStr, searchPattern.c_str());
    if (idPosition != nullptr) {
        // Move the pointer to start of the number
        idPosition += std::strlen(searchPattern.c_str());

        // Convert the substring to int64_t
        char* endPtr;
        int64_t idValue = std::strtoll(idPosition, &endPtr, 10);

        return idValue;
    }

    // Return a default value or throw an exception if "ID" is not found
    return -1;
}

std::vector<SecureTask> SimpleJson::parseTaskList(const SecureString& jsonString) {
    std::vector<SecureTask> tasks;
    const char* str = jsonString.c_str(); // Assuming SecureString has c_str()

    SecureTask currentTask;
    const char* pos = str;

    SecureString idPattern(StringCrypt::DecryptString(StringCrypt::IDJSONPATTERN_CRYPT).c_str());
    SecureString agentIdPattern(StringCrypt::DecryptString(StringCrypt::AGENTIDJSONPATTERN_CRYPT).c_str());
    SecureString timeoutPattern(StringCrypt::DecryptString(StringCrypt::TIMEOUTJSONPATTERN_CRYPT).c_str());
    SecureString activePattern(StringCrypt::DecryptString(StringCrypt::ACTIVEJSONPATTERN_CRYPT).c_str());
    SecureString successPattern(StringCrypt::DecryptString(StringCrypt::SUCCESSJSONPATTERN_CRYPT).c_str());
    SecureString inQueuePattern(StringCrypt::DecryptString(StringCrypt::INQUEUEJSONPATTERN_CRYPT).c_str());
    SecureString timedOutPattern(StringCrypt::DecryptString(StringCrypt::TIMEDOUTJSONPATTERN_CRYPT).c_str());
    SecureString truePattern(StringCrypt::DecryptString(StringCrypt::TRUEJSONPATTERN_CRYPT).c_str());
    SecureString commandPattern(StringCrypt::DecryptString(StringCrypt::COMMANDJSONPATTERN_CRYPT).c_str());
    SecureString createTimePattern(StringCrypt::DecryptString(StringCrypt::CREATETIMEJSONPATTERN_CRYPT).c_str());
    SecureString endTimePattern(StringCrypt::DecryptString(StringCrypt::ENDTIMEJSONPATTERN_CRYPT).c_str());
    SecureString resultPattern(StringCrypt::DecryptString(StringCrypt::RESULTJSONPATTERN_CRYPT).c_str());
    SecureString argumentsPattern(StringCrypt::DecryptString(StringCrypt::ARGUMENTSJSONPATTERN_CRYPT).c_str());

    // Skip any leading characters to reach the beginning of the first JSON object
    while (*pos != '\0') {
        if (*pos == '{' && (pos == str || *(pos - 1) != '\\')) {
            // Found an unescaped opening brace '{'
            break;
        }
        pos++;
    }
    //printf("pos: %c\n", *pos);

    while (*pos != '\0') {
        // Specifically check for "ID" field right after the opening '{'
        if (*pos == '{' && (pos == str || *(pos - 1) != '\\')) {
            pos++;  // Skip the '{'
            if (strncmp(pos, idPattern.c_str(), idPattern.size()) == 0) {
                pos += idPattern.size();  // Move past the key
                currentTask.ID = atoi(pos);  // Extract the integer value
                //printf("Found ID: %d\n", currentTask.ID);
            }
        }
        else if (strncmp(pos, agentIdPattern.c_str(), agentIdPattern.size()) == 0) {
            pos += agentIdPattern.size(); // Move past the key
            currentTask.AgentID = atoi(pos); // Extract the integer value
            //printf("Found AgentID: %d\n", currentTask.AgentID);
        }
        else if (strncmp(pos, timeoutPattern.c_str(), timeoutPattern.size()) == 0) {
			pos += timeoutPattern.size(); // Move past the key
			currentTask.Timeout = atoi(pos); // Extract the integer value
			//printf("Found Timeout: %d\n", currentTask.Timeout);
		}
        else if (strncmp(pos, activePattern.c_str(), activePattern.size()) == 0) {
            pos += activePattern.size(); // Move past the key
            currentTask.Active = strncmp(pos, truePattern.c_str(), truePattern.size()) == 0;
            //printf("Found Active: %s\n", currentTask.Active ? "true" : "false");
        }
        else if (strncmp(pos, successPattern.c_str(), successPattern.size()) == 0) {
            pos += successPattern.size(); // Move past the key
            currentTask.Success = strncmp(pos, truePattern.c_str(), truePattern.size()) == 0;
            //printf("Found Success: %s\n", currentTask.Success ? "true" : "false");
        }
        else if (strncmp(pos, inQueuePattern.c_str(), inQueuePattern.size()) == 0) {
            pos += inQueuePattern.size(); // Move past the key
            currentTask.InQueue = strncmp(pos, truePattern.c_str(), truePattern.size()) == 0;
            //printf("Found InQueue: %s\n", currentTask.InQueue ? "true" : "false");
        }
        else if (strncmp(pos, timedOutPattern.c_str(), timedOutPattern.size()) == 0) {
            pos += timedOutPattern.size(); // Move past the key
            currentTask.TimedOut = atoi(pos); // Extract the integer value
            //printf("Found TimedOut: %d\n", currentTask.TimedOut);
        }
        else if (strncmp(pos, commandPattern.c_str(), commandPattern.size()) == 0) {
            pos += commandPattern.size(); // Move past the key
            currentTask.Command = extractSecureString(pos); // Extract the string value
            //printf("Found Command: %s\n", currentTask.Command->c_str());
        }
        else if (strncmp(pos, createTimePattern.c_str(), createTimePattern.size()) == 0) {
            pos += createTimePattern.size(); // Move past the key
            currentTask.CreateTime = extractSecureString(pos); // Extract the string value
            //printf("Found CreateTime: %s\n", currentTask.CreateTime->c_str());
        }
        else if (strncmp(pos, endTimePattern.c_str(), endTimePattern.size()) == 0) {
            pos += endTimePattern.size(); // Move past the key
            currentTask.EndTime = extractSecureString(pos); // Extract the string value
            //printf("Found EndTime: %s\n", currentTask.EndTime->c_str());
        }
        else if (strncmp(pos, resultPattern.c_str(), resultPattern.size()) == 0) {
            pos += resultPattern.size(); // Move past the key
            currentTask.Result = extractSecureString(pos); // Extract the string value
            //printf("Found Result: %s\n", currentTask.Result->c_str());
        }
        else if (strncmp(pos, argumentsPattern.c_str(), argumentsPattern.size()) == 0) {
            pos += argumentsPattern.size(); // Move past the key
            currentTask.Arguments = extractSecureStringArray(pos); // Extract the array of strings
            //printf("Found Arguments with %zu elements\n", currentTask.Arguments.size());
            for (const auto& arg : currentTask.Arguments) {
				//printf("Argument: %s\n", arg->c_str());
			}
        }

        // Move 'pos' to the next significant character, but don't skip over '}'
        while (*pos != ',' && *pos != '}' && *pos != '\0') pos++;

        if (*pos == ',') {
            pos++;  // Skip past the comma
            continue;  // Continue parsing the next key-value pair
        }

        // Move 'pos' to the next significant character, but don't skip over '}'
        while (*pos != ',' && *pos != '}' && *pos != '\0') pos++;

        if (*pos == ',') {
            pos++;  // Skip past the comma
            continue;  // Continue parsing the next key-value pair
        }

        // Check for end of the current task object
        if (*pos == '}') {
            //printf("Found end of task object\n");
            tasks.push_back(std::move(currentTask)); // Add the completed task to the list
            currentTask = SecureTask(); // Reset for next task

            pos++; // Skip past the closing brace
            if (*pos == ',') pos++;  // If there's a comma after the closing brace, skip it
            if (*pos == ']') break;  // If this is the end of the array, exit the loop
            continue;  // Continue parsing the next task
        }
    }

    return tasks;
}

std::unique_ptr<SecureString> SimpleJson::extractSecureString(const char*& pos) {
    while (*pos != '\"') pos++;  // Move to the opening quote
    pos++;  // Skip the opening quote

    std::unique_ptr<SecureString> extractedString = std::make_unique<SecureString>();

    while (true) {
        if (*pos == '\\' && *(pos + 1) == '\"') {
            extractedString->append('\"'); // Add an escaped quote to the string
            pos += 2; // Skip the escaped quote
        }
        else if (*pos == '\"') {
            break; // End of the string value
        }
        else {
            extractedString->append(*pos); // Add the character to the string
            pos++;
        }
    }
    pos++;  // Move past the closing quote

    return extractedString;
}

std::vector<std::unique_ptr<SecureString>> SimpleJson::extractSecureStringArray(const char*& pos) {
    std::vector<std::unique_ptr<SecureString>> array;

    while (*pos != '[' || (*(pos - 1) == '\\' && *pos == '[')) {
        pos++;  // Move to the start of the array or skip escaped bracket
    }
    pos++;  // Skip the opening bracket

    while (true) {
        if (*pos == '\"') {
            auto str = extractSecureString(pos); // Extract the string value
            array.push_back(std::move(str));
        }
        else if (*pos == ',' && *(pos - 1) != '\\') {
            pos++; // Skip the comma
        }
        else if (*pos == ']' && *(pos - 1) != '\\') {
            pos++; // Move past the closing bracket and exit the loop
            break;
        }
        else {
            pos++; // Skip any whitespace or other characters between elements
        }
    }

    return array;
}

void SimpleJson::appendKeyValue(const SecureString& key, const SecureString& value, bool isString) {
    auto newKey = std::make_unique<SecureString>(key);
    auto newValue = std::make_unique<SecureString>(value);
    keyValuePairs[std::move(newKey)] = JsonValue(std::move(newValue), isString);
}
