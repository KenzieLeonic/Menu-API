package th.ac.ku.menu.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import th.ac.ku.menu.model.Menu;
import th.ac.ku.menu.service.MenuService;
import java.util.List;
import java.util.UUID;

//ทำ rest api ให้เรา
@RestController
//เป็น base url
@RequestMapping("/menu")
public class MenuController {
    @Autowired
    private MenuService service; //Autowired ที่ service

    @GetMapping //มา method นี้อัตโนมัติ
    public List<Menu> getAll(){
        return service.getAll();
    }
    @PostMapping
    public Menu create(@RequestBody Menu menu){
        return service.create(menu);// เรียก method นี้จาก service

    }
    @GetMapping("/{id}")
    public Menu getMenuById(@PathVariable UUID id) {
        return service.getMenuById(id);
    }

    @PutMapping
    public Menu update(@RequestBody Menu menu) {
        return service.update(menu);
    }

    @DeleteMapping("/{id}")
    public Menu delete(@PathVariable UUID id) {
        return service.delete(id);
    }

    @GetMapping("/name/{name}")
    public Menu getMenuByName(@PathVariable String name) {
        return service.getMenuByName(name);
    }

    @GetMapping("/category/{category}")
    public List<Menu> getMenuByCategory(@PathVariable String category) {
        return service.getMenuByCategory(category);
    }
}
