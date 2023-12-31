package security.services;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import security.entities.Role;
import security.repositories.RoleRepository;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;

    public Role getUserRole() {
        return roleRepository.findByName("ROLE_USER").get();
    }
}
