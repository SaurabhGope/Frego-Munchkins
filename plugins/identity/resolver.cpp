#include <map>
#include <utility>

#include "frego/plugins/identity.hpp"

namespace frego::plugins {

IdentityResolver::IdentityResolver(const net::OuiDb* oui, IdFactory new_id) : oui_(oui), new_id_(std::move(new_id)) {}

void IdentityResolver::remember(const domain::KnownIdentity& known) {
    if (known.identity == "weak") weak_[known.mac + "@" + known.ip] = known.device_id;
    else strong_[known.mac] = known.device_id;
}

void IdentityResolver::remember_shared(const std::string& mac) { shared_.insert(mac); }

std::vector<std::string> IdentityResolver::take_new_shared() { return std::exchange(new_shared_, {}); }

DeviceIdentified IdentityResolver::identify(const net::Mac& mac, const std::string& ip, bool shared, bool is_self) {
    const std::string m = mac.str();
    auto& index = shared ? weak_ : strong_;
    const std::string key = shared ? m + "@" + ip : m;
    bool created = false;
    auto it = index.find(key);
    if (it == index.end()) {
        it = index.emplace(key, new_id_()).first;
        created = true;
    }
    std::optional<std::string> vendor;
    if (!shared && oui_)
        if (auto v = oui_->lookup(mac)) vendor = std::string(*v);
    return DeviceIdentified{it->second,         ip,       m,       vendor, shared ? "weak" : "strong",
                            mac.locally_administered(), is_self, created, is_self ? "self" : "arp"};
}

std::vector<DeviceIdentified> IdentityResolver::resolve(const NeighborSnapshot& snapshot) {
    std::map<std::string, std::set<std::string>> ips_by_mac;
    for (const auto& e : snapshot.entries)
        if (auto mac = net::Mac::parse(e.mac)) ips_by_mac[mac->str()].insert(e.ip);
    for (const auto& [mac, ips] : ips_by_mac)
        if (ips.size() >= 2 && shared_.insert(mac).second) new_shared_.push_back(mac);

    std::vector<DeviceIdentified> out;
    for (const auto& e : snapshot.entries) {
        auto mac = net::Mac::parse(e.mac);
        if (!mac) continue;
        out.push_back(identify(*mac, e.ip, shared_.contains(mac->str()), false));
    }
    if (auto self = net::Mac::parse(snapshot.self.mac)) out.push_back(identify(*self, snapshot.self.ip, false, true));
    return out;
}

}  // namespace frego::plugins
