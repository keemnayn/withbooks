package kr.withbooks.web.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.stereotype.Component;

import kr.withbooks.web.entity.Book;
import kr.withbooks.web.entity.Category;

@Component
public class JsonParser {

	public Integer parser(List<Book> list, String jsonResponse){
		
        // JSON 문자열을 JSONObject로 변환
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");

        JSONObject jsonObject = new JSONObject(jsonResponse);

        // 에러코드가 뜬 경우
        if(jsonObject.has("errorCode")){
            System.out.println(jsonObject.getInt("errorCode"));
            System.out.println(jsonObject.getString("errorMessage"));
            return null;
        }

        // 검색 정보가 없는 경우
        int totalResults = jsonObject.getInt("totalResults");
        if(totalResults==0){
            System.out.println("검색 정보가 없음");
            return null;
        }
        
        // JSON에서 페이징 정보 꺼내기
        int startIndex = jsonObject.getInt("startIndex");
        int itemsPerPage = jsonObject.getInt("itemsPerPage");

        // items 배열에서 각 책 정보를 가져와 List<Book>에 저장
        JSONArray items = jsonObject.getJSONArray("item");
        
        for (int i = 0; i < items.length(); i++) {
            JSONObject item = items.getJSONObject(i);
            // 필요한 정보 추가
            // ...

            // cover : coversum -> cover500 변경
            String cover = item.getString("cover").replaceAll("sum", "500");
            
            // categoryName : 그대로 박아넣기
            String categoryName = item.getString("categoryName");

            // categoryId : 국내도서>예술/대중문화>영화/드라마>영화이야기
            // > 기준으로 잘라서 arr[1]인 예술/대중문화를 찾고
            // Category와 비교 -> 맞는 id를 categoryId로 삽입

            Book book = new Book();
            try {
                book = Book.builder()
                            .categoryName(categoryName)
                            .categoryId(item.getLong("categoryId"))
                            .title(item.getString("title"))
                            .purchaseLink(item.getString("link"))
                            .author(item.getString("author"))
                            .pubDate(dateFormat.parse(item.getString("pubDate")))
                            .description(item.getString("description"))
                            .isbn13(item.getString("isbn13"))
                            .price(item.getInt("priceStandard"))
                            .cover(cover)
                            // .categoryId(categoryId)
                            .publisher(item.getString("publisher"))
                            .build();
            } catch (JSONException | ParseException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            // List<Book>에 책 정보 추가
            list.add(book);
        }
        // 저장된 책 정보 출력
        // for (int i = 0; i < bookList.size(); i++) {
        //     System.out.println("Book " + (i + 1) + ": " + bookList.get(i).toString());
        // }
        // Map<String, Object> map = new HashMap<>();
        // map.put("list", bookList);
        
        // if(bookList.size() == 1)
        //     return map;

        // map.put("totalResults", totalResults);

        // return map;
        return null;
		
	}
	
	

}
