import {Component, OnInit} from '@angular/core';
import { RouterOutlet } from '@angular/router';
import {Service} from "./service/service";
import {CommonModule} from "@angular/common";
import {HttpResponse} from "@angular/common/http";

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet, CommonModule],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent implements OnInit {

  data: any
  publicData: any

  constructor(private http: Service) {
  }

  ngOnInit(): void {
    if (!this.data) {
      this.http.getResource(this.http.bffUrl).subscribe(
        data => this.data = data
      )
    }
  }

  login() {
    window.open("http://127.0.0.1:8082/oauth2/authorization/spring", "_self")
  }

  logout() {
    this.http.logout().subscribe(
      (data: HttpResponse<any>)  => window.open(data.headers.get("Location")?.toString(), "_self")
    );
  }

  fetch() {
    this.http.getResource(this.http.bffUrl + "authenticated").subscribe(
      data => this.publicData = data
    )
  }
}
