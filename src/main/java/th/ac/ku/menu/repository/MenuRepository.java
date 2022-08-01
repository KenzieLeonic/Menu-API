package th.ac.ku.menu.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import th.ac.ku.menu.model.Menu;

import java.util.List;
import java.util.UUID;

//interface นี้ extend จาก jpa จะสร้างข้อมูลให้อัตโนมัติ
@Repository //เป็นตัวเชื่อมต่อฐานข้อมูล
//T = type of object
//P = type of key
public interface MenuRepository extends JpaRepository<Menu, UUID> {
    Menu findByName(String name);
    List<Menu> findByCategory(String category);
}
