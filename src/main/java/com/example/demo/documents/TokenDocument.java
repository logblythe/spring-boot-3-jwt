package com.example.demo.documents;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document("token")
public class TokenDocument {
    @Id
    private String id;
    private String token;
    private Boolean revoked;
    private Boolean expired;
    private String userId;
    private String tokenType;
}
