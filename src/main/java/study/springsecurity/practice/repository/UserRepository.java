package study.springsecurity.practice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.springsecurity.practice.domain.entity.Users;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {
    Optional<Users> findByEmail(String email);
}
