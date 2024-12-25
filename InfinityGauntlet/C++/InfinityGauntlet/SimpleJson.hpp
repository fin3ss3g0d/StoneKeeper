#pragma once
#include <map>
#include <memory>
#include <string>
#include <vector>

class SecureString;
struct SecureTask;

struct JsonValue {
    std::unique_ptr<SecureString> value;
    bool isString;
    bool isVector;

    // Default constructor
    JsonValue() : isString(true), isVector(false) {}

    // Constructor for string value
    JsonValue(std::unique_ptr<SecureString> val, bool isStr)
        : value(std::move(val)), isString(isStr), isVector(false) {}

    // Constructor for vector value
    JsonValue(bool isVec)
        : value(std::make_unique<SecureString>("")), isString(false), isVector(isVec) {}
};

class SimpleJson {
public:
    SimpleJson();
    ~SimpleJson();

    void addString(const char* key, const SecureString& value);
    void addInt64(const char* key, int64_t value);
    void addBool(const char* key, bool value);
    void addStringVector(const char* key, const std::vector<std::unique_ptr<SecureString>>& values);
    int64_t extractID(const SecureString& jsonString);
    std::vector<SecureTask> parseTaskList(const SecureString& jsonString);
    std::unique_ptr<SecureString> extractSecureString(const char*& pos);
    std::vector<std::unique_ptr<SecureString>> extractSecureStringArray(const char*& pos);

    SecureString dump();

private:
    std::map<std::shared_ptr<SecureString>, JsonValue> keyValuePairs;
    std::unique_ptr<SecureString> jsonString;

    void appendKeyValue(const SecureString& key, const SecureString& value, bool isString);
};
