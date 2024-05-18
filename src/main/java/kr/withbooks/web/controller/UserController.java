package kr.withbooks.web.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.withbooks.web.config.CustomUserDetails;
import kr.withbooks.web.controller.form.UserJoinForm;
import kr.withbooks.web.entity.User;
import kr.withbooks.web.service.JoinService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/user")
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final JoinService service;

    @GetMapping("/join")
    public String joinForm(Model model){
        User user = new User();
        model.addAttribute("user", user);
        return "user/join";
    }

    @PostMapping("/join")
    public String joinUser(
            @Validated
            @ModelAttribute(name = "user") UserJoinForm form,
            BindingResult bindingResult) {

        if (bindingResult.hasErrors()) {
            log.info("errors={}", bindingResult);
            return "user/join";
        }

        //성공 로직
        User user = new User();
        user.setEmail(form.getEmail());
        user.setPassword(form.getPassword());
        user.setNickname(form.getNickname());
        user.setGender(form.getGender());
        user.setIntro(form.getIntro());

        log.info("user={}", user);

        service.join(user);

        return "redirect:/user/login";
    }



    @GetMapping("login")
    public  String login(HttpServletRequest request , HttpServletResponse response, @AuthenticationPrincipal CustomUserDetails userDetails){

        if(userDetails !=null)
            return "redirect:/shorts/list";


        return  "user/login";
    }

}