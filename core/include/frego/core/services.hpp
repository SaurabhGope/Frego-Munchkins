#pragma once

#include <format>
#include <stdexcept>
#include <typeindex>
#include <unordered_map>

namespace frego {

// Typed lookup for shared objects the core doesn't know about (e.g. the domain store).
// fregod provides them; plugins fetch them with ctx.service<T>(). This keeps the core
// free of domain types (DESIGN §2, M1).
class Services {
public:
    template <class T>
    void provide(T& object) {
        objects_[std::type_index(typeid(T))] = &object;
    }

    template <class T>
    T* find() const {
        auto it = objects_.find(std::type_index(typeid(T)));
        return it == objects_.end() ? nullptr : static_cast<T*>(it->second);
    }

    template <class T>
    T& get() const {
        if (T* p = find<T>()) return *p;
        throw std::logic_error(std::format("service not provided: {}", typeid(T).name()));
    }

private:
    std::unordered_map<std::type_index, void*> objects_;
};

}  // namespace frego
