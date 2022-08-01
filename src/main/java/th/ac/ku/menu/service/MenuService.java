package th.ac.ku.menu.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import th.ac.ku.menu.model.Menu;
import th.ac.ku.menu.repository.MenuRepository;

import java.util.List;
import java.util.UUID;

@Service
public class MenuService {
    @Autowired //ให้ string framework โยนข้อมูลจากข้างนอกลงใน db อัตโนมัติ
    private MenuRepository menuRepository;

    //เหมือน select all ทำหน้าที่ get ข้อมูลมา
    public List<Menu> getAll() {
        return menuRepository.findAll(); //เรียกใช้งาน = select all
    }

    //ใช้ create insert ข้อมูล
    //รับเป็น object เข้ามา แล้ว insert object เข้ามาให้
    public Menu create(Menu menu) {
        Menu record = menuRepository.save(menu); //คืนค่าเป็นตัว object generate auto id มาให้
        return record; //for output
    }

    public Menu getMenuById(UUID id) {
        return menuRepository.findById(id).get();
    }

    public Menu update(Menu requestBody) {
        UUID id = requestBody.getId();
        Menu record = menuRepository.findById(id).get();
        record.setName(requestBody.getName());
        record.setPrice(requestBody.getPrice());
        record.setCategory(requestBody.getCategory());
        record = menuRepository.save(record);
        return record;
    }

    //delete
    public Menu delete(UUID id) {
        Menu record = menuRepository.findById(id).get();
        menuRepository.deleteById(id);
        return record;
    }

    public Menu getMenuByName(String name) {
        return menuRepository.findByName(name);
    }

    public List<Menu> getMenuByCategory(String category) {
        return menuRepository.findByCategory(category);
    }

}
