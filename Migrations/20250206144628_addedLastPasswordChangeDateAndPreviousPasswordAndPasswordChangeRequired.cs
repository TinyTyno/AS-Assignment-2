using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AS_Assignment_2.Migrations
{
    /// <inheritdoc />
    public partial class addedLastPasswordChangeDateAndPreviousPasswordAndPasswordChangeRequired : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "LastPasswordChangeDate",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<bool>(
                name: "PasswordChangeRequired",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "PreviousPasswords",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LastPasswordChangeDate",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "PasswordChangeRequired",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "PreviousPasswords",
                table: "AspNetUsers");
        }
    }
}
