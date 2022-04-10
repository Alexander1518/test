package web.testUsers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import web.model.Provider;
import web.model.Role;
import web.model.User;
import web.service.RoleService;
import web.service.UserService;

import javax.annotation.PostConstruct;
import java.util.HashSet;
import java.util.Set;

@Component
public class DBInit {
    private final UserService userService;
    private final RoleService roleService;

    @Autowired
    public DBInit(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @PostConstruct
    @Transactional
    void testUser() {
        roleService.saveRole(new Role("ADMIN"));
        roleService.saveRole(new Role("USER"));

        Set<Role> setAdmin = new HashSet<>();
        setAdmin.add(roleService.getRoleByName("ADMIN"));
        setAdmin.add(roleService.getRoleByName("USER"));
        userService.saveOrUpdate(new User("admin", "admin", 21, "admin@mail.ru", "ADMIN", Provider.GOOGLE, setAdmin));

        Set<Role> setUser = new HashSet<>();
        setUser.add(roleService.getRoleByName("USER"));
        userService.saveOrUpdate(new User("user", "user", 22, "user@mail.ru", "USER", Provider.GOOGLE, setUser));
    }
}