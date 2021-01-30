<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use App\Enums\BookCondition;
use App\Enums\BookStatus;

class CreateBookshelfTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('bookshelf', function (Blueprint $table) {
            $table->id();
            $table->integer("user_id");
            $table->integer("book_id");
            $table->tinyInteger('condition')->unsigned()->default(BookCondition::Good);
            $table->tinyInteger('status')->unsigned()->default(BookStatus::Available);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('user_library');
    }
}