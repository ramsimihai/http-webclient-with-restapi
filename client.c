#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helpers.h"
#include "requests.h"
#include "parson.h"
#include <ctype.h>

#define SERV_ADDR "34.241.4.235"
#define PORT 8080
#define LINE_SIZE 256
#define MAX_LEN 128
#define MAX_REG 300
#define MAX_DATA 1024

// verify if a string is a number
int is_number(char s[])
{
    for (int i = 0; s[i]!= '\n'; i++)
    {
        if (isdigit(s[i]) == 0)
              return 0;
    }
    return 1;
}

// verify if a string has any space in it
int has_space(char s[])
{
    for (int i = 0; s[i] != '\n'; i++) {
        if (s[i] == ' ') {
            return 0;
        }
    }

    return 1;
}

// make a register request to the server with an username & password given
void register_request(char username[MAX_LEN], char password[MAX_LEN], int sockfd)
{
    char *response;

    JSON_Value *body_value = json_value_init_object();
    JSON_Object *body_object = json_value_get_object(body_value);
    JSON_Status buff_status;

    // parse the input into json object
    char *message;
    char *buffer = malloc(MAX_REG * sizeof(char));
    json_object_set_string(body_object, "username", username);
    json_object_set_string(body_object, "password", password);
    buff_status = json_serialize_to_buffer(body_value, buffer, MAX_REG);

    if (buff_status < 0) {
        free(buffer);
        perror("Couldn't do json serialize to buffer\n");
    }

    // computes the message as a post request
    message = compute_post_request(SERV_ADDR, "/api/v1/tema/auth/register", "application/json", &buffer, 1, NULL, 0);
    // sends the message to the server & receive its response
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // parse error code
    int req_id;
    sscanf(response, "%*s %d", &req_id);
    
    free(buffer);
    json_value_free(body_value);
    free(message);
    free(response);

    // treats if the request was succesful or not
    if (req_id / 100 == 2) {
        printf("Your account has been created!\n");
    } else {
        printf("Your account couldn't be created!\n");
    }
}


// makes a login request to the server with an username & password, the action
// will return a cookie that will be stored for later purposes
int login_request(char username[MAX_LEN], char password[MAX_LEN], int sockfd, char **cookie)
{
    char *response;

    JSON_Value *body_value = json_value_init_object();
    JSON_Object *body_object = json_value_get_object(body_value);
    JSON_Status buff_status;

    // parses the input into a json object
    char *message;
    char *buffer = malloc(MAX_REG * sizeof(char));
    json_object_set_string(body_object, "username", username);
    json_object_set_string(body_object, "password", password);
    buff_status = json_serialize_to_buffer(body_value, buffer, MAX_REG);

    if (buff_status < 0) {
        free(buffer);
        perror("Couldn't do json serialize to buffer\n");
    }

    // computes the message to a post request and communicate with the server
    message = compute_post_request(SERV_ADDR, "/api/v1/tema/auth/login", "application/json", &buffer, 1, NULL, 0);
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // parses the error code
    int req_id;
    sscanf(response, "%*s %d", &req_id);
    
    free(buffer);
    json_value_free(body_value);

    // treats the error code
    if (req_id / 100 == 2) {
        printf("You are now logged in!\n");
    } else {
        free(message);
        free(response);
        printf("Invalid credentials!\n");
        return -1;
    }

    // if the login was successful, store the cookie gotten from the server
    *cookie = malloc(sizeof(char) * MAX_DATA);

    char *aux = strstr(response, "connect.sid");
    sscanf(aux, "%s", *cookie);

    free(message);
    free(response);

    return 0;
}

// makes a get access into a library, if the user is not logged in,
// they wouldn't get access
int get_access(int sockfd, char *cookie, char **jwt)
{
    char *response, *message;
    JSON_Value *body_value;

    // checks if cookie is null & computes a get request
    if (cookie == NULL) {
        message = compute_get_request(SERV_ADDR, "/api/v1/tema/library/access", NULL, NULL, 1);
    } else {
        message = compute_get_request(SERV_ADDR, "/api/v1/tema/library/access", NULL, &cookie, 1);
    }

    // sends the request to the server and get the answer
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // parses the error code
    int req_id;
    sscanf(response, "%*s %d", &req_id);

    // gets to the starting point of the body of the content
    // received from server
    char *aux = strstr(response, "{\"");

    // parses the json gotten from the server using parson library
    body_value = json_parse_string(aux);
    JSON_Object *body_object = json_value_get_object(body_value);

    if (req_id / 100 == 2) {
        // the access was permitted to the library so got a token that will be
        // stored for later purposes
        char aux_jwt[MAX_DATA];
        sprintf(aux_jwt, "%s", json_object_get_string(body_object, "token"));

        *jwt = strdup(aux_jwt);

        printf("You just got access to the library!\n");
    } else {
        // the acces was not permitted to the library so printed error message
        char error_str[MAX_LEN];
        sprintf(error_str, "%s", json_object_get_string(body_object, "error"));
        printf("%s\n", error_str);

        json_value_free(body_value);
        free(message);
        free(response);
        return -1;
    }
    
    json_value_free(body_value);
    free(message);
    free(response);

    return 0;
}

// make a logout request to exit from the current user
int logout_request(int sockfd, char *cookie)
{
    char *response, *message;
    JSON_Value *body_value;

    // checks if cookie is null & computes a get request
    if (cookie == NULL) {
        message = compute_get_request(SERV_ADDR, "/api/v1/tema/auth/logout", NULL, NULL, 1);
    } else {
        message = compute_get_request(SERV_ADDR, "/api/v1/tema/auth/logout", NULL, &cookie, 1);
    }

    // sends the request to the server and get the answer
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // parses the error code
    int req_id;
    sscanf(response, "%*s %d", &req_id);

    // gets to the starting point of the body of the content
    // received from server
    char *aux = strstr(response, "{\"");

    // parses the json gotten from the server using parson library
    body_value = json_parse_string(aux);
    JSON_Object *body_object = json_value_get_object(body_value);

    if (req_id / 100 == 2) {
        printf("You have succesfully logout!\n");
    } else {
        // couldnt logged out so printed an error message
        char error_str[MAX_LEN];
        sprintf(error_str, "%s", json_object_get_string(body_object, "error"));
        printf("%s\n", error_str);

        json_value_free(body_value);
        free(message);
        free(response);
        return -1;
    }
    
    json_value_free(body_value);
    free(message);
    free(response);

    return 0;
}

// makes a get request from the library to get all the books, if the user
// is logged in and has a token that he accessed the library
int get_books_request(int sockfd, char **jwt)
{
    char *response, *message;

    // computes message
    message = compute_get_request_auth(SERV_ADDR, "/api/v1/tema/library/books", NULL, NULL, 0, jwt);
    // sends message to server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // parses the error code
    int req_id;
    sscanf(response, "%*s %d", &req_id);

    if (req_id / 100 == 2) {
        // gets to the starting point of the body of the content
        // received from server
        char *aux = strstr(response, "[");;
        JSON_Value *recv_body = json_parse_string(aux);

        // parses a json array gotten from the server
        JSON_Array *recv_array = json_value_get_array(recv_body);
        if (json_array_get_count(recv_array) < 1) {
            // if there is no json object in the json array prints error
            printf("There is no book in the library!\n");
        } else {
            // otherwise prints all the books gotten from the json array
            printf("These are the books in the library: \n");
            for (int i = 0; i < json_array_get_count(recv_array); i++) {
                JSON_Object *book = json_array_get_object(recv_array, i);

                printf("{\n \"id\": %0.0f\n \"title\": %s}\n", json_object_get_number(book, "id"),
                                        json_object_get_string(book, "title"));
            }
        }
        json_value_free(recv_body);
    } else {
        // gets to the starting point of the body of the content
        // received from server
        char *aux = strstr(response, "{");

        // parses the json object cause it will be an error message only
        JSON_Value *recv_body = json_parse_string(aux);
        JSON_Object *recv_object = json_value_get_object(recv_body);
        char error_str[MAX_LEN];
        sprintf(error_str, "%s", json_object_get_string(recv_object, "error"));

        // checks if the user has no jwt so prints error
        if (strncmp(error_str, "Error", 5) == 0) {
            printf("Authorization invalid!\n");
        } else {
            printf("%s\n", error_str);
        }

        json_value_free(recv_body);
        free(message);
        free(response);
        return -1;
    }

    free(message);
    free(response);

    return 0;
}

// makes a get request from the library to get the info about a book,
// if the user is logged in, has a token that he accessed the library,
int get_book_by_id_request(int sockfd, int id, char **jwt)
{
    char *response;
    char *message;

    char url[MAX_DATA];
    char id_char[MAX_LEN];

    memset(url, 0, MAX_DATA);
    memset(id_char, 0, MAX_LEN);

    // parses url with the book id
    sprintf(id_char, "%d", id);
    memset(url, 0, MAX_DATA);
    strcat(url, "/api/v1/tema/library/books/");
    strcat(url, id_char);

    // computes message
    message = compute_get_request_auth(SERV_ADDR, url, NULL, NULL, 0, jwt);
    // sends message to server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    // parses response
    int req_id;
    sscanf(response, "%*s %d", &req_id);

    char *aux = strstr(response, "{");
    JSON_Value *recv_body = json_parse_string(aux);

    if (req_id / 100 == 2) {      
        JSON_Object *book = json_value_get_object(recv_body);

        // prints the requested book details if the request was succesful
        printf("This is the requested book:\n{\n \"id\": %d\n \"title\": %s", id,
                                json_object_get_string(book, "title"));
        printf(" \"author\": %s \"publisher:\" %s \"genre\": %s \"page_count\": %0.0f\n}\n", json_object_get_string(book, "author"),
                    json_object_get_string(book, "publisher"),
                    json_object_get_string(book, "genre"),
                    json_object_get_number(book, "page_count"));
    } else {
        JSON_Object *recv_object = json_value_get_object(recv_body);
        char error_str[MAX_LEN];

        // prints an error message if the book doesnt exist in the library
        // or if the user doesnt have a token
        sprintf(error_str, "%s", json_object_get_string(recv_object, "error"));
        if (strncmp(error_str, "Error", 5) == 0) {
            printf("Authorization invalid!\n");
        } else if (strncmp(error_str, "No book", 7) == 0) {
            printf("No book was found with the id: %d!\n", id);
        } else {
            printf("%s\n", error_str);
        }

        json_value_free(recv_body);
        free(message);
        free(response);
        return -1;
    }

    json_value_free(recv_body);
    free(message);
    free(response);

    return 0;
}

// make a delete request to delete a book from the library
// if the user is logged in and has an jwt
int delete_book_by_id_request(int sockfd, int id, char **jwt)
{
    char *response;
    char *message;

    char url[MAX_DATA];
    char id_char[MAX_LEN];

    memset(url, 0, MAX_DATA);
    memset(id_char, 0, MAX_LEN);

    sprintf(id_char, "%d", id);
    memset(url, 0, MAX_DATA);
    strcat(url, "/api/v1/tema/library/books/");
    strcat(url, id_char);

    // computes message
    message = compute_delete_request_auth(SERV_ADDR, url, jwt);
    // sends message to server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    int req_id;
    sscanf(response, "%*s %d", &req_id);

    if (req_id / 100 == 2) {      
        printf("The book with the id: %d has been deleted succesfully!\n", id);
    } else {
        char *aux = strstr(response, "{");;
        JSON_Value *recv_body = json_parse_string(aux);
        JSON_Object *recv_object = json_value_get_object(recv_body);
        char error_str[MAX_LEN];
        sprintf(error_str, "%s", json_object_get_string(recv_object, "error"));

        // prints an error message if the book doesnt exist in the library
        // or if the user doesnt have a token
        if (strncmp(error_str, "Error", 5) == 0) {
            printf("Authorization invalid!\n");
        } else if (strncmp(error_str, "No book", 7) == 0) {
            printf("No book was found with the id: %d!\n", id);
        } else {
            printf("%s\n", error_str);
        }

        json_value_free(recv_body);
        free(message);
        free(response);
        return -1;
    }

    free(message);
    free(response);

    return 0;
}

// make a post request to add a book in the library if the user is logged in
// and the post
int add_book_request(char title[MAX_LEN], char author[MAX_LEN], char genre[MAX_LEN],
                     int page_count, char publisher[MAX_LEN], int sockfd, char **jwt)
{
    char *response;

    JSON_Value *body_value = json_value_init_object();
    JSON_Object *body_object = json_value_get_object(body_value);
    JSON_Status buff_status;

    char *message;
    char *buffer = malloc(MAX_DATA * sizeof(char));
    json_object_set_string(body_object, "title", title);
    json_object_set_string(body_object, "author", author);
    json_object_set_string(body_object, "genre", genre);
    json_object_set_string(body_object, "publisher", publisher);
    json_object_set_number(body_object, "page_count", page_count);
    buff_status = json_serialize_to_buffer(body_value, buffer, MAX_REG);

    if (buff_status < 0) {
        free(buffer);
        perror("Couldn't do json serialize to buffer\n");
    }

    // computes message
    message = compute_post_request_auth(SERV_ADDR, "/api/v1/tema/library/books", "application/json", &buffer, 1, NULL, 0, jwt);
    
    // sends message to server
    send_to_server(sockfd, message);
    response = receive_from_server(sockfd);

    int req_id;
    sscanf(response, "%*s %d", &req_id);
    
    free(buffer);
    json_value_free(body_value);

    char *aux = strstr(response, "{\"");
    JSON_Value *recv_body = json_parse_string(aux);
    JSON_Object *recv_object = json_value_get_object(recv_body);

    if (req_id / 100 == 2) {
        char aux_string[MAX_DATA];
        sprintf(aux_string, "%s", json_object_get_string(recv_object, "token"));

        printf("You just added a new book!\n");
    } else {
        char error_str[MAX_LEN];
        sprintf(error_str, "%s", json_object_get_string(recv_object, "error"));
        if (strncmp(error_str, "Error", 5) == 0) {
            printf("Authorization invalid!\n");
        } else {
            printf("%s\n", error_str);
        }

        json_value_free(recv_body);
        free(message);
        free(response);
        return -1;
    }

    json_value_free(recv_body);
    free(message);
    free(response);

    return 0;
}

int main(void)
{
    int sockfd;
    char *cookie = NULL;
    char *jwt = NULL;
    int is_logged = -1;
    int got_jwt = -1;

    printf("Available commands: register, login, enter_library, get_books, get_book, add_book, delete_book, logout, exit.\n");

    while(1) {
        // opens a tcp connection to the server every time a new command
        // is given
        sockfd = open_connection(SERV_ADDR, PORT, AF_INET, SOCK_STREAM, 0);

        char line[LINE_SIZE];
        memset(line, 0, LINE_SIZE);
        fgets(line, LINE_SIZE, stdin);

        if (strcmp(line, "register\n") == 0) {
            char username[MAX_LEN], password[MAX_LEN];
            memset(username, 0, MAX_LEN);
            memset(password, 0, MAX_LEN);
            int ok_username = 0, ok_password = 0;

            printf("username=");
            memset(line, 0, LINE_SIZE);
            fgets(line, LINE_SIZE, stdin);
            sscanf(line, "%s ", username);
            ok_username = has_space(line);
            
            printf("password=");
            memset(line, 0, LINE_SIZE);
            fgets(line, LINE_SIZE, stdin);
            sscanf(line, "%s ", password);
            ok_password = has_space(line);

            // checks if user is logged in
            if (is_logged == 0) {
                printf("You cannot register if you are already logged in!\n");
            } else {
                // checks if the username has spaces
                if (ok_username == 0) {
                    printf("The username is invalid! Try another username.\n");
                }

                // checks if the password has spaces
                if (ok_password == 0) {
                    printf("The password is invalid! Try another password.\n");
                }
                
                // if there are spaces it couldnt make a new account
                if (ok_password == 0 || ok_username == 0) {
                    register_request(NULL, NULL, sockfd);
                } else {
                    register_request(username, password, sockfd);
                }
            }

            close(sockfd);
        } else if (strcmp(line, "login\n") == 0) {
            char username[MAX_LEN], password[MAX_LEN];
            memset(line, 0, LINE_SIZE);

            // cause the verification of username was made on the register
            // part, there is no use to check if username / password has spaces
            printf("username=");
            fgets(line, LINE_SIZE, stdin);
            sscanf(line, "%s ", username);
            
            printf("password=");
            memset(line, 0, LINE_SIZE);
            fgets(line, LINE_SIZE, stdin);
            sscanf(line, "%s ", password);

            // checks if there is a user logged in
            if (is_logged != 0) {
                is_logged = login_request(username, password, sockfd, &cookie);

                // restart jwt token cause another account just logged in
                if (is_logged == 0) {
                    got_jwt = -1;
                }
            } else {
                printf("Another account is already logged in!\n");
            }

            close(sockfd);
        } else if (strcmp(line, "enter_library\n") == 0) {
            // checks if there is a jwt token already & the account is logged in
            if (got_jwt != 0) {
                got_jwt = get_access(sockfd, cookie, &jwt);
            } else {
                printf("You already have access to the library!\n");
            }
            close(sockfd);
        } else if (strcmp(line, "get_books\n") == 0) {
            get_books_request(sockfd, &jwt);
            close(sockfd);
        } else if (strcmp(line, "get_book\n") == 0) {
            printf("id=");
            memset(line, 0, LINE_SIZE);
            fgets(line, LINE_SIZE, stdin);
            int is_no = is_number(line);

            // checks if the id inserted is a number
            if (is_no == 0) {
                printf("The id inserted is not a number!\n");
                continue;
            }

            get_book_by_id_request(sockfd, atoi(line), &jwt);
        } else if (strcmp(line, "add_book\n") == 0) {
            char title[MAX_LEN], author[MAX_LEN], genre[MAX_LEN], publisher[MAX_LEN];
            int page_count;

            printf("title=");
            memset(line, 0, LINE_SIZE);
            fgets(line, LINE_SIZE, stdin);
            strcpy(title, line);
            
            printf("author=");
            memset(line, 0, LINE_SIZE);
            fgets(line, LINE_SIZE, stdin);
            strcpy(author, line);

            printf("genre=");
            memset(line, 0, LINE_SIZE);
            fgets(line, LINE_SIZE, stdin);
            strcpy(genre, line);

            printf("publisher=");
            memset(line, 0, LINE_SIZE);
            fgets(line, LINE_SIZE, stdin);
            strcpy(publisher, line);

            printf("page_count=");
            memset(line, 0, LINE_SIZE);
            fgets(line, LINE_SIZE, stdin);
            int is_no = is_number(line);
            page_count = atoi(line);

            if (is_no == 0) {
                printf("The page_count inserted is not a number!\n");
                close(sockfd);
                continue;
            }

            add_book_request(title, author, genre, page_count, publisher, sockfd, &jwt);
            close(sockfd);
        } else if (strcmp(line, "delete_book\n") == 0) {
            printf("id=");
            memset(line, 0, LINE_SIZE);
            fgets(line, LINE_SIZE, stdin);
            int is_no = is_number(line);
            if (is_no == 0) {
                printf("The id inserted is not a number!\n");
                continue;
            }

            delete_book_by_id_request(sockfd, atoi(line), &jwt);
        } else if (strcmp(line, "logout\n") == 0) {
            int logout_no = logout_request(sockfd, cookie);

            // when an user logs out, the is_logged and got_jwt restarts
            // and the jwt and cookie are freed
            if (logout_no == 0) {
                is_logged = -1;
                got_jwt = -1;

                if (jwt != NULL)
                    free(jwt);

                if (cookie != NULL)
                    free(cookie);

                jwt = NULL;
            }
            close(sockfd);
        } else if (strcmp(line, "exit\n") == 0) {
            if (jwt != NULL && is_logged == 0)
                    free(jwt);

            if (cookie != NULL && is_logged == 0)
                free(cookie);

            close(sockfd);
            return 0;
        } else {
            continue;
        }
    }
}
