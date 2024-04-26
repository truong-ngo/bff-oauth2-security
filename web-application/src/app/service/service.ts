import { Injectable } from '@angular/core';
import {HttpClient, HttpHeaders, HttpResponse} from "@angular/common/http";
import { Observable } from "rxjs";

@Injectable({
  providedIn: 'root'
})
export class Service {

  constructor(private http: HttpClient) {}

  public bffUrl = "http://127.0.0.1:8082/api/";

  getResource(url: string) : Observable<any> {
    return this.http.get(url);
  }

  logout(): Observable<any> {
    return this.http.post("http://127.0.0.1:8082/logout", {}, {observe: "response"});
  }
}
